#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# GDB backtrace forest visualizer with wrapped-line handling.
#
# Usage:
#   gdb_bt_forest.py path/to/bt.txt
#
# Key features:
# - Robust unwrapping of lines split by terminal width (joins continuations
#   until the next '#<num>' or 'Thread <id>' header).
# - Merge stacks into a prefix-tree and show counts/percentages.
# - Filters (--keep/--strip), grouping granularity, depth/top pruning, colors.
#
# Author: ChatGPT  |  License: MIT
#
import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Iterable, Optional

FRAME_RE = re.compile(r"^#(?P<idx>\d+)\s+(?P<rest>.+)$")
THREAD_RE = re.compile(r"^Thread\s+(?P<tid>\d+)\b")
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
    A record starts with either:
      - a frame line:   '^#<num> ...'
      - a thread line:  '^Thread <id> ...'
    Subsequent non-empty lines that do NOT start with either are considered
    continuations and concatenated (hyphenated endings get de-hyphenated).
    Blank lines flush the current record.
    Non-record lines before any record starters are ignored.
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
    children: Dict[str, "Node"] = field(default_factory=dict)
    sample_ids: List[int] = field(default_factory=list)

    def child(self, k: str) -> "Node":
        if k not in self.children:
            self.children[k] = Node(k)
        return self.children[k]

def frame_key_from_rest(rest: str, grouping: str) -> Tuple[str, Optional[str]]:
    """Return (display_key, file_or_lib_or_path)."""
    # Strip leading address if present: "0x... in func ..."
    m = ADDR_PREFIX_RE.match(rest)
    if m:
        rest = m.group(2)

    # Extract function/method portion up to ' at ' or ' from '
    func_part = rest.split(" at ")[0].split(" from ")[0].strip()

    # Remove parameter lists for 'name' and 'name+file*' modes to reduce cardinality
    func_name = func_part
    paren = func_part.find("(")
    if paren != -1:
        func_name = func_part[:paren].strip()

    file_or_lib = None
    line_no = None
    m = AT_FILE_RE.search(rest)
    if m:
        file_or_lib = m.group(1)  # path
        line_no = m.group(2)      # may be None
    else:
        m2 = FROM_LIB_RE.search(rest)
        if m2:
            file_or_lib = m2.group(1)  # .so path

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
            # For 'from lib.so' or missing line info, fall back to file only
            return (f"{func_name or func_part}  [{file_or_lib}]", file_or_lib)
        else:
            return (func_name or func_part, None)
    else:  # full
        full = re.sub(r"\s+", " ", rest.strip())
        return (full, file_or_lib)

def parse_stacks(lines: Iterable[str], grouping: str, keep_regs, strip_regs, per_thread=False, debug=False) -> Dict[str, List[List[str]]]:
    stacks_by_thread: Dict[str, List[List[str]]] = defaultdict(list)
    cur_frames: List[str] = []
    cur_thread = "ALL"

    for line in lines:
        mt = THREAD_RE.match(line)
        if mt:
            if per_thread:
                cur_thread = f"Thread-{mt.group('tid')}"
            if cur_frames:
                stacks_by_thread[cur_thread].append(cur_frames)
                cur_frames = []
            continue

        mf = FRAME_RE.match(line)
        if not mf:
            if debug:
                print(f"[debug] skip non-frame: {line}")
            continue

        idx = int(mf.group("idx"))
        rest = mf.group("rest").strip()
        key, _ = frame_key_from_rest(rest, grouping)

        # Filter phase
        if keep_regs and not match_any(key, keep_regs):
            continue
        if strip_regs and match_any(key, strip_regs):
            continue

        if idx == 0 and cur_frames:
            stacks_by_thread[cur_thread].append(cur_frames)
            cur_frames = []

        cur_frames.append(key)

    if cur_frames:
        stacks_by_thread[cur_thread].append(cur_frames)

    return stacks_by_thread

def build_forest(stacks: List[List[str]], reverse=False) -> "Node":
    norm = []
    for s in stacks:
        if s:
            norm.append(s if reverse else list(reversed(s)))
    root = Node("<root>")
    for sid, stack in enumerate(norm, 1):
        node = root
        node.count += 1
        for k in stack:
            node = node.child(k)
            node.count += 1
        node.sample_ids.append(sid)
    return root

def print_forest(root: "Node", total: int, args):
    if args.ascii:
        T, L, V, S = "+-- ", "`-- ", "|   ", "    "
    else:
        T, L, V, S = "├── ", "└── ", "│   ", "    "

    def fmt_node(k: str, c: int) -> str:
        pct = (100.0 * c / total) if total else 0.0
        name = k
        if not args.no_color:
            if pct >= 50: name = ansi(name, "1;31", True)
            elif pct >= 20: name = ansi(name, "1;33", True)
            elif pct >= 5: name = ansi(name, "1;36", True)
        return f"{name}  [{c} | {pct:.1f}%]"

    def rec(node: "Node", pref: str, depth: int):
        items = sorted(node.children.items(), key=lambda kv: (-kv[1].count, kv[0]))
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

    if args.input == "-":
        data = sys.stdin.read().splitlines()
    else:
        with open(args.input, "r", encoding="utf-8", errors="replace") as f:
            data = f.read().splitlines()

    keep_regs = compile_regexes(args.keep) if args.keep else []
    strip_regs = compile_regexes(args.strip) if args.strip else []

    unwrapped = reflow_wrapped(data, debug=args.debug)

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
