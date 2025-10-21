#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GDB backtrace forest visualizer + call graph exporter
- Robust unwrapping for terminal-wrapped lines
- Correct thread partitioning (flush-before-switch fix)
- Default sibling order is input-stable (--order stable)
- Grouping: name | name+file | name+file+line | full
- Robust function-name extraction: remove only the trailing parameter list;
  preserve operator() and parentheses inside template non-type args.
- NEW: Build a global call graph (per thread or all) and export as Mermaid or JSON.
"""
import argparse
import json
import os
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
    ap = argparse.ArgumentParser(description="Merge GDB backtraces into a call forest (and optionally export a call graph).")
    ap.add_argument("input", help="Path to text file containing GDB bt outputs (or - for stdin).")
    # tree display options
    ap.add_argument("-n", "--top", type=int, default=None, help="Show only top N roots by samples.")
    ap.add_argument("-p", "--min-percent", type=float, default=0.0, help="Prune nodes below this percent of total stacks (tree only).")
    ap.add_argument("-d", "--max-depth", type=int, default=None, help="Limit printed tree depth (tree only).")
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
    ap.add_argument("--threads", action="store_true", help="Build a forest/graph per thread if present.")
    ap.add_argument("--debug", action="store_true", help="Debug parsing.")
    # graph export options (minimal set)
    ap.add_argument("--graph", choices=["mermaid","json"], action="append",
                    help="Export call graph in the given format (can be used multiple times).")
    ap.add_argument("--graph-out", help="Output path when exporting a single graph (single format & no --threads).")
    ap.add_argument("--graph-out-pattern", help="Filename template for graphs with placeholders {thread} and {ext}, e.g., 'callgraph_{thread}.{ext}'.")
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

def frame_key_from_rest(rest: str, grouping: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Extract display key (by grouping) + optional file and line metadata."""
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
        key = func_name or func_part
    elif grouping == "name+file":
        key = f"{func_name or func_part}  [{file_or_lib}]" if file_or_lib else (func_name or func_part)
    elif grouping == "name+file+line":
        if file_or_lib and line_no:
            key = f"{func_name or func_part}  [{file_or_lib}:{line_no}]"
        elif file_or_lib:
            key = f"{func_name or func_part}  [{file_or_lib}]"
        else:
            key = func_name or func_part
    else:  # full
        key = re.sub(r"\s+", " ", rest.strip())

    return key, file_or_lib, line_no

def parse_stacks(lines: Iterable[str], grouping: str, keep_regs, strip_regs, per_thread=False, debug=False) -> Tuple[Dict[str, List[List[str]]], Dict[str, Dict[str, Dict[str, Optional[str]]]]]:
    """Parse lines into stacks.
    Returns:
      stacks_by_thread: {thread: [ [frame_key,...], ... ]}
      meta_by_thread:   {thread: {frame_key: {"file":..., "line":...}, ...}}
    """
    stacks_by_thread: Dict[str, List[List[str]]] = defaultdict(list)
    meta_by_thread: Dict[str, Dict[str, Dict[str, Optional[str]]]] = defaultdict(dict)
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
        key, file_or_lib, line_no = frame_key_from_rest(rest, grouping)

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

        # Keep first-seen file/line meta for this key
        if key not in meta_by_thread[cur_thread]:
            meta_by_thread[cur_thread][key] = {"file": file_or_lib, "line": line_no}

    if cur_frames:
        stacks_by_thread[cur_thread].append(cur_frames)

    return stacks_by_thread, meta_by_thread

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

# ------------------ Call Graph construction & export ------------------

def sanitize_id(label: str, used: set, prefix: str = "n") -> str:
    """Produce a stable, human-friendly id: n1, n2, ... ensuring uniqueness by order of first appearance."""
    i = len(used) + 1
    nid = f"{prefix}{i}"
    while nid in used:
        i += 1
        nid = f"{prefix}{i}"
    used.add(nid)
    return nid

def build_call_graph(stacks: List[List[str]]) -> Tuple[Dict[str, int], Dict[Tuple[str,str], int]]:
    """From list of stacks (each is list of frame keys from root->leaf), build node and edge counts.
       Node count is per-stack (a node appears in a stack => +1 once). Edge count sums per occurrence.
    """
    node_counts: Dict[str, int] = defaultdict(int)
    edge_counts: Dict[Tuple[str,str], int] = defaultdict(int)

    for stack in stacks:
        if not stack:
            continue
        seen = set()
        # node per-stack counting
        for k in stack:
            if k not in seen:
                node_counts[k] += 1
                seen.add(k)
        # edges per occurrence
        for i in range(len(stack) - 1):
            u, v = stack[i], stack[i+1]
            edge_counts[(u, v)] += 1

    return dict(node_counts), dict(edge_counts)

def export_graph_mermaid(path: str, node_counts: Dict[str,int], edge_counts: Dict[Tuple[str,str],int],
                         total_stacks: int, meta: Dict[str, Dict[str, Optional[str]]]):
    """Write a Mermaid flowchart file."""
    # assign IDs in stable insertion order by first occurrence in node_counts
    used = set()
    id_of: Dict[str,str] = {}
    for key in node_counts.keys():
        id_of[key] = sanitize_id(key, used, "n")

    lines = []
    lines.append("graph LR")
    # nodes
    for key, cnt in node_counts.items():
        nid = id_of[key]
        label = key.replace('"', '\\"')
        lines.append(f'  {nid}["{label}"]')
    # edges
    for (u, v), ecnt in edge_counts.items():
        lines.append(f"  {id_of[u]} --> {id_of[v]}")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def export_graph_json(path: str, thread_name: str, node_counts: Dict[str,int], edge_counts: Dict[Tuple[str,str],int],
                      total_stacks: int, meta: Dict[str, Dict[str, Optional[str]]]):
    used = set()
    id_of: Dict[str,str] = {}
    for key in node_counts.keys():
        id_of[key] = sanitize_id(key, used, "n")

    nodes = []
    for key, cnt in node_counts.items():
        info = {"id": id_of[key], "label": key, "count": cnt, "pct": (100.0*cnt/total_stacks if total_stacks else 0.0)}
        m = meta.get(key)
        if m:
            if m.get("file") is not None:
                info["file"] = m.get("file")
            if m.get("line") is not None:
                try:
                    info["line"] = int(m.get("line"))
                except (TypeError, ValueError):
                    info["line"] = m.get("line")
        nodes.append(info)

    edges = []
    for (u, v), ecnt in edge_counts.items():
        edges.append({
            "src": id_of[u],
            "dst": id_of[v],
            "count": ecnt,
            "pct": (100.0*ecnt/total_stacks if total_stacks else 0.0),
        })

    data = {"thread": thread_name, "total_stacks": total_stacks, "nodes": nodes, "edges": edges}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def determine_output_paths(graph_formats: List[str], threads_enabled: bool, thread_key: str,
                           graph_out: Optional[str], graph_out_pattern: Optional[str]) -> Dict[str, str]:
    """
    Decide where to write outputs for this (possibly per-thread) graph.
    Returns a mapping of format -> path.
    Rules:
      - If multiple formats or threads involved, use pattern (if provided) or default 'callgraph_{thread}.{ext}'.
      - If single format and no threads, and --graph-out is provided, use it.
      - Otherwise default to 'callgraph_{thread}.{ext}'.
    """
    ext_map = {"mermaid": "mmd", "json": "json"}
    paths: Dict[str, str] = {}

    multiple = len(graph_formats) > 1 or threads_enabled
    if multiple:
        pattern = graph_out_pattern or "callgraph_{thread}.{ext}"
        for fmt in graph_formats:
            ext = ext_map[fmt]
            paths[fmt] = pattern.format(thread=thread_key, ext=ext)
        return paths

    # single format, possibly graph_out
    fmt = graph_formats[0]
    if graph_out and not threads_enabled:
        paths[fmt] = graph_out
    else:
        pattern = graph_out_pattern or "callgraph_{thread}.{ext}"
        paths[fmt] = pattern.format(thread=thread_key, ext=ext_map[fmt])
    return paths

# ---------------------------------------------------------------------

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

    # 2) parse into stacks (optionally per-thread), also collect meta
    stacks_by_thread, meta_by_thread = parse_stacks(unwrapped, args.group, keep_regs, strip_regs, per_thread=args.threads, debug=args.debug)

    if not stacks_by_thread or all(len(v)==0 for v in stacks_by_thread.values()):
        print("No stacks parsed. Ensure your input contains GDB 'bt' frames (#0, #1, ...) or thread headers.", file=sys.stderr)
        sys.exit(1)

    # 3) print forest(s)
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

    # 4) optionally export call graph(s)
    if args.graph:
        for tid, stacks in stacks_by_thread.items():
            if not stacks:
                continue
            # Normalize stacks to root->leaf order for graphs
            norm_stacks = []
            for s in stacks:
                if s:
                    norm_stacks.append(s if args.reverse else list(reversed(s)))

            node_counts, edge_counts = build_call_graph(norm_stacks)
            total = len(stacks)
            meta = meta_by_thread.get(tid, {})

            paths = determine_output_paths(args.graph, args.threads, tid if args.threads else "ALL",
                                           args.graph_out, args.graph_out_pattern)

            for fmt, out_path in paths.items():
                # ensure parent directory exists if needed
                odir = os.path.dirname(out_path)
                if odir and not os.path.isdir(odir):
                    os.makedirs(odir, exist_ok=True)
                if fmt == "mermaid":
                    export_graph_mermaid(out_path, node_counts, edge_counts, total, meta)
                elif fmt == "json":
                    export_graph_json(out_path, tid if args.threads else "ALL", node_counts, edge_counts, total, meta)

if __name__ == "__main__":
    main()
