#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GDB backtrace forest visualizer (robust edition)
- Handles terminal-wrapped lines (e.g., from Neovim terminal copy)
- Correctly partitions by thread (flush-before-switch fix)
- Default sibling order is input-stable (--order stable)
- Supports grouping: name | name+file | name+file+line | full
- Robust function-name extraction that removes only the trailing parameter list,
  keeping names like operator() and templates with parentheses in non-type params.
"""
import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Iterable, Optional

# Frame and thread header detection
FRAME_RE = re.compile(r"^#(?P<idx>\d+)\s+(?P<rest>.+)$")
THREAD_RE = re.compile(r"^Thread\s+(?P<tid>\d+)\b")

# Heuristics for file/lib detection
AT_FILE_RE = re.compile(r"\s+at\s+([^\s:]+)(?::(\d+))?")
FROM_LIB_RE = re.compile(r"\s+from\s+(\S+)")
ADDR_PREFIX_RE = re.compile(r"^(0x[0-9a-fA-F]+)\s+in\s+(.+)$")

def parse_args():
    ap = argparse.ArgumentParser(description="Merge GDB backtraces into a call forest (with wrapped-line handling).")
    ap.add_argument("input", help="Path to text file containing GDB bt outputs (or - for stdin).")
    ap.add_argument("-n", "--top", type=int, default=None, help="Show only top N roots by samples.")
    ap.add_argument("-p", "--min-percent", type=float, default=0.0, help="Prune nodes below this percent of total stacks.")
    ap.add_argument("-d", "--max-depth", type=int, default=None, help="Limit printed tree depth.")
    ap.add_argument("-g", "--group", choices=["name","name+file","name+file+line","full"], default="name",
                    help="Frame grouping granularity.")
    ap.add_argument("--order", choices=["count","name","stable"], default="stable",
                    help="Sibling order: by count (desc), by name (asc), or stable (input order).")
    ap.add_argument("-s", "--strip", action="append", default=[], help="Drop frames that match this regex (can repeat).")
    ap.add_argument("--keep", action="append", default=[], help="Keep only frames that match this regex (filter-in).")
    ap.add_argument("--reverse", action="store_true", help="Do NOT reverse stacks (treat #0 as root).")
    style = ap.add_mutually_exclusive_group()
    style.add_argument("--unicode", action="store_true", help="Use Unicode box drawing (default).")
    style.add_argument("--ascii", action="store_true", help="Use ASCII tree drawing.")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI color.")
    ap.add_argument("--show-samples", action="store_true", help="Show sample ids at leaves.")
    ap.add_argument("--threads", action="store_true", help="Build a forest per thread id if present.")
    ap.add_argument("--debug", action="store_true", help="Debug parsing.")
    return ap.parse_args()

def ansi(s, code, enabled=True):
    if not enabled:
        return s
    return f"\033[{code}m{s}\033[0m"

def compile_regexes(pats: List[str]) -> List[re.Pattern]:
    try:
        return [re.compile(p) for p in pats]
    except re.error as e:
        sys.stderr.write(f"[error] invalid regex: {e}\n")
        sys.exit(2)

def match_any(s: str, regs: List[re.Pattern]) -> bool:
    return any(r.search(s) for r in regs)

def reflow_wrapped(lines: Iterable[str], debug: bool=False) -> List[str]:
    """Join terminal-wrapped logical records.
    Records start with '^#<num>' or '^Thread <id>'.
    Continuations (non-empty, non-starter lines) are concatenated.
    If a line ends with '-', drop it and concat the next line directly.
    Blank lines flush the current record.
    """
    out: List[str] = []
    buf: Optional[str] = None

    def append_continuation(base: str, cont: str) -> str:
        if base.endswith('-'):
            return base[:-1] + cont.lstrip()
        return base + cont

    for raw in lines:
        line = raw.rstrip("\n")
        if FRAME_RE.match(line) or THREAD_RE.match(line):
            if buf is not None:
                out.append(buf)
            buf = line
            continue
        if buf is None:
            continue
        if not line.strip():
            out.append(buf)
            buf = None
            continue
        buf = append_continuation(buf, line)

    if buf is not None:
        out.append(buf)

    if debug:
        for i, l in enumerate(out, 1):
            print(f"[unwrap {i:03d}] {l}")
    return out

@dataclass
class Node:
    key: str
    count: int = 0
    children: Dict[str, "Node"] = field(default_factory=dict)  # insertion-ordered
    sample_ids: List[int] = field(default_factory=list)

    def child(self, k: str) -> "Node":
        if k not in self.children:
            self.children[k] = Node(k)
        return self.children[k]

# --- Robust function-name extraction helpers ---

def _trim_trailing_qualifiers(s: str) -> str:
    """Remove trailing qualifiers after the parameter list (const, noexcept(...), throw(...), &, &&)."""
    prev = None
    while prev != s:
        prev = s
        s = re.sub(r"\s+(const|volatile|mutable|noexcept(?:\s*\([^)]*\))?)\s*$", "", s)
        s = re.sub(r"\s+throw\s*\([^)]*\)\s*$", "", s)
        s = re.sub(r"\s*[&]{1,2}\s*$", "", s)  # &, &&
    return s.strip()

def _strip_trailing_param_list(func_part: str) -> str:
    """Remove only the final '(...)' parameter list from the end, keeping names like 'operator()' intact.
    Examples:
      'ns::Functor::operator()()'                    -> 'ns::Functor::operator()'
      'std::function<void()>::operator()() const'    -> 'std::function<void()>::operator()'
      'Foo<(int)3>::bar()'                           -> 'Foo<(int)3>::bar'
      'Baz<(MyEnum)MyEnum::Val>::qux() noexcept'     -> 'Baz<(MyEnum)MyEnum::Val>::qux'
      'Worker::run() const&'                         -> 'Worker::run'
    """
    s = _trim_trailing_qualifiers(func_part)
    j = s.rfind(')')
    if j == -1:
        return s
    # Ensure the trailing token is ')'
    if j != len(s) - 1:
        s2 = s[:j+1].rstrip()
        if j != len(s2) - 1:
            return s
    # Scan backward to find the matching '('
    depth = 0
    i = j
    while i >= 0:
        if s[i] == ')':
            depth += 1
        elif s[i] == '(':
            depth -= 1
            if depth == 0:
                return s[:i].rstrip()
        i -= 1
    return s  # unmatched; keep as-is

def frame_key_from_rest(rest: str, grouping: str) -> Tuple[str, Optional[str]]:
    """Extract a display key from a frame line, honoring grouping mode."""
    # Strip leading address prefix: "0x... in ..."
    m = ADDR_PREFIX_RE.match(rest)
    if m:
        rest = m.group(2)

    # Function/method portion up to ' at ' or ' from '
    func_part = rest.split(" at ")[0].split(" from ")[0].strip()

    # Robustly remove only the final parameter list
    func_name = _strip_trailing_param_list(func_part)

    # File/lib + line metadata
    file_or_lib = None
    line_no = None
    m = AT_FILE_RE.search(rest)
    if m:
        file_or_lib = m.group(1)
        line_no = m.group(2)
    else:
        m2 = FROM_LIB_RE.search(rest)
        if m2:
            file_or_lib = m2.group(1)

    if grouping == "name":
        return (func_name or func_part, None)
    elif grouping == "name+file":
        if file_or_lib:
            return (f"{func_name or func_part}  [{file_or_lib}]", file_or_lib)
        return (func_name or func_part, None)
    elif grouping == "name+file+line":
        if file_or_lib and line_no:
            return (f"{func_name or func_part}  [{file_or_lib}:{line_no}]", file_or_lib)
        elif file_or_lib:
            return (f"{func_name or func_part}  [{file_or_lib}]", file_or_lib)
        else:
            return (func_name or func_part, None)
    else:  # full
        full = re.sub(r"\s+", " ", rest.strip())
        return (full, file_or_lib)

def parse_stacks(lines: Iterable[str], grouping: str, keep_regs, strip_regs, per_thread=False, debug=False) -> Dict[str, List[List[str]]]:
    """Parse lines into stacks. Thread headers flush the current thread's partial stack (bugfix)."""
    stacks_by_thread: Dict[str, List[List[str]]] = defaultdict(list)
    cur_frames: List[str] = []
    cur_thread = "ALL"

    for line in lines:
        mt = THREAD_RE.match(line)
        if mt:
            # Flush current frames to the current thread BEFORE switching
            if cur_frames:
                stacks_by_thread[cur_thread].append(cur_frames)
                cur_frames = []
            if per_thread:
                cur_thread = f"Thread-{mt.group('tid')}"
            continue

        mf = FRAME_RE.match(line)
        if not mf:
            if debug:
                print(f"[debug] skip non-frame: {line}")
            continue

        idx = int(mf.group("idx"))
        rest = mf.group("rest").strip()
        key, _ = frame_key_from_rest(rest, grouping)

        # Filters
        if keep_regs and not match_any(key, keep_regs):
            continue
        if strip_regs and match_any(key, strip_regs):
            continue

        # New stack starts at #0; flush the previous stack
        if idx == 0 and cur_frames:
            stacks_by_thread[cur_thread].append(cur_frames)
            cur_frames = []

        cur_frames.append(key)

    if cur_frames:
        stacks_by_thread[cur_thread].append(cur_frames)

    return stacks_by_thread

def build_forest(stacks: List[List[str]], reverse=False) -> "Node":
    """Build a prefix forest (rooted at '<root>'); reverse=False means outermost as root."""
    norm = []
    for s in stacks:
        if s:
            norm.append(s if reverse else list(reversed(s)))
    root = Node("<root>")
    for sid, stack in enumerate(norm, 1):
        node = root
        node.count += 1
        for k in stack:
            node = node.child(k)  # preserves insertion order of first encounter
            node.count += 1
        node.sample_ids.append(sid)
    return root

def iter_children(node: "Node", order: str):
    if order == "stable":
        return node.children.items()
    elif order == "name":
        return iter(sorted(node.children.items(), key=lambda kv: kv[0]))
    else:  # "count"
        return iter(sorted(node.children.items(), key=lambda kv: (-kv[1].count, kv[0])))

def print_forest(root: "Node", total: int, args):
    # Charset
    if args.ascii:
        T, L, V, S = "+-- ", "`-- ", "|   ", "    "
    else:
        T, L, V, S = "├── ", "└── ", "│   ", "    "

    def fmt_node(k: str, c: int) -> str:
        pct = (100.0 * c / total) if total else 0.0
        name = k
        if not args.no_color:
            if pct >= 50: name = ansi(name, "1;31", True)      # bold red
            elif pct >= 20: name = ansi(name, "1;33", True)    # bold yellow
            elif pct >= 5: name = ansi(name, "1;36", True)     # bold cyan
        return f"{name}  [{c} | {pct:.1f}%]"

    def rec(node: "Node", pref: str, depth: int):
        items = list(iter_children(node, args.order))
        if args.top is not None and depth == 0:
            items = items[:args.top]
        n = len(items)
        for i, (k, ch) in enumerate(items):
            pct = (100.0 * ch.count / total) if total else 0.0
            if pct < args.min_percent:
                continue
            connector = L if i == n - 1 else T
            print(pref + connector + fmt_node(k, ch.count))
            if args.show_samples and ch.sample_ids:
                print(pref + ("    " if i == n - 1 else V) + f"  samples: {', '.join(map(str, ch.sample_ids))}")
            next_depth = depth + 1
            if args.max_depth is None or next_depth < args.max_depth:
                new_pref = pref + (S if i == n - 1 else V)
                rec(ch, new_pref, next_depth)

    rec(root, "", 0)

def main():
    args = parse_args()

    # Read data
    if args.input == "-":
        data = sys.stdin.read().splitlines()
    else:
        with open(args.input, "r", encoding="utf-8", errors="replace") as f:
            data = f.read().splitlines()

    keep_regs = compile_regexes(args.keep) if args.keep else []
    strip_regs = compile_regexes(args.strip) if args.strip else []

    # 1) unwrap hard-wrapped lines
    unwrapped = reflow_wrapped(data, debug=args.debug)

    # 2) parse into stacks (optionally per-thread)
    stacks_by_thread = parse_stacks(unwrapped, args.group, keep_regs, strip_regs, per_thread=args.threads, debug=args.debug)

    if not stacks_by_thread or all(len(v)==0 for v in stacks_by_thread.values()):
        print("No stacks parsed. Ensure your input contains GDB 'bt' frames (#0, #1, ...) or thread headers.", file=sys.stderr)
        sys.exit(1)

    first = True
    for tid, stacks in stacks_by_thread.items():
        if not stacks:
            continue
        total = len(stacks)
        root = build_forest(stacks, reverse=args.reverse)
        title = f"=== {tid} :: {total} stacks ===" if args.threads else f"=== {total} stacks ==="
        if not args.no_color:
            title = ansi(title, "1;34", True)
        if not first:
            print()
        print(title)
        print_forest(root, total, args)
        first = False

if __name__ == "__main__":
    main()
