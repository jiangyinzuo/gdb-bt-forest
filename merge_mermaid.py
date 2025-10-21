#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
import argparse
from pathlib import Path
from typing import Dict, Tuple, List, Set, Optional

# ---------- Regex helpers ----------

GRAPH_DIR_RE = re.compile(r'^\s*graph\s+([A-Za-z]{2})\s*$', re.IGNORECASE)

# Node declaration patterns: id followed by a shape with a label inside; allow quoted/unquoted.
# Capture id and label (first non-None among groups).
NODE_RE = re.compile(
    r'''^\s*
    (?P<id>[A-Za-z_][A-Za-z0-9_\-]*)
    \s*
    (?:                           # one of several node declaration shapes
        \[\s*"(?P<label_qb>.*?)"\s*\]           |  # ["Label"]
        \(\s*"(?P<label_qp>.*?)"\s*\)           |  # ("Label")
        \{\s*"(?P<label_qc>.*?)"\s*\}           |  # {"Label"}
        \(\(\s*"(?P<label_qpp>.*?)"\s*\)\)      |  # (("Label"))
        \{\{\s*"(?P<label_qcc>.*?)"\s*\}\}      |  # {{"Label"}}
        \[\s*(?P<label_b>[^\]]+?)\s*\]          |  # [Label]
        \(\s*(?P<label_p>[^)]+?)\s*\)           |  # (Label)
        \{\s*(?P<label_c>[^}]+?)\s*\}           |  # {Label}
        \(\(\s*(?P<label_pp>[^)]+?)\s*\)\)      |  # ((Label))
        \{\{\s*(?P<label_cc>[^}]+?)\s*\}\}         # {{Label}}
    )
    \s*$''',
    re.VERBOSE,
)

# Directed edge: A -- "text" --> B   or   A --> B   (capture optional label text)
DIRECTED_WITH_LABEL = re.compile(
    r'^\s*(?P<src>[A-Za-z_][A-Za-z0-9_\-]*)\s*--\s*(?:"(?P<label>.*?)"\s*)?->\s*(?P<dst>[A-Za-z_][A-Za-z0-9_\-]*)\s*$'
)

# A stricter directed matcher as fallback (no label capture)
DIRECTED_EDGE_RE = re.compile(
    r'^\s*(?P<src>[A-Za-z_][A-Za-z0-9_\-]*)\s*-->\s*(?P<dst>[A-Za-z_][A-Za-z0-9_\-]*)\s*$'
)

# Undirected edge: A --- B
UNDIRECTED_EDGE_RE = re.compile(
    r'^\s*(?P<src>[A-Za-z_][A-Za-z0-9_\-]*)\s*---\s*(?P<dst>[A-Za-z_][A-Za-z0-9_\-]*)\s*$'
)

# ---------- Data structures ----------

class Graph:
    def __init__(self, direction: str = "LR"):
        self.direction = direction
        # Node maps
        self.label_to_id: Dict[str, str] = {}     # canonical ID chosen for label
        self.id_to_label: Dict[str, str] = {}     # reverse map for output
        # Edges stored as tuples: (src_label, arrow, edge_label, dst_label)
        # arrow is one of: '-->' or '---'
        self.edges: Set[Tuple[str, str, str, str]] = set()
        self.seen_label_order: List[str] = []     # stable order of labels

    def ensure_node(self, label: str, prefer_id: Optional[str] = None):
        label = label.strip()
        if label not in self.label_to_id:
            # Choose ID: prefer first-seen concrete id; if absent/occupied, generate new
            if prefer_id and prefer_id not in self.id_to_label:
                node_id = prefer_id
            else:
                node_id = self._generate_new_id()
            self.label_to_id[label] = node_id
            self.id_to_label[node_id] = label
            self.seen_label_order.append(label)

    def _generate_new_id(self) -> str:
        # Use prefix 'n' + increasing integer avoiding collisions with existing ids
        k = 1
        existing = set(self.id_to_label.keys())
        while True:
            cand = f"n{k}"
            if cand not in existing:
                return cand
            k += 1

    def add_directed_edge(self, src_label: str, dst_label: str, edge_label: str = ""):
        self.edges.add((src_label, '-->', edge_label, dst_label))

    def add_undirected_edge(self, src_label: str, dst_label: str):
        a, b = sorted([src_label.strip(), dst_label.strip()])
        self.edges.add((a, '---', '', b))


def parse_label_from_node_line(line: str):
    m = NODE_RE.match(line)
    if not m:
        return None, None
    node_id = m.group('id')
    label = None
    for key in ['label_qb','label_qp','label_qc','label_qpp','label_qcc','label_b','label_p','label_c','label_pp','label_cc']:
        val = m.group(key)
        if val is not None:
            label = val.strip()
            break
    return node_id, label


def parse_graph_blocks(text: str) -> List[Tuple[str, List[str]]]:
    # Return list of (direction, lines_in_block) for each graph block.
    lines = text.splitlines()
    blocks: List[Tuple[str, List[str]]] = []
    cur_dir = None
    cur_lines: List[str] = []

    for ln in lines:
        g = GRAPH_DIR_RE.match(ln)
        if g:
            if cur_dir is not None:
                blocks.append((cur_dir, cur_lines))
            cur_dir = g.group(1).upper()
            cur_lines = []
        else:
            if cur_dir is not None:
                cur_lines.append(ln)

    if cur_dir is not None:
        blocks.append((cur_dir, cur_lines))

    return blocks


def merge_files(paths: List[Path]) -> Graph:
    merged = Graph(direction="LR")
    have_dir = False

    for p in paths:
        text = p.read_text(encoding='utf-8', errors='ignore')
        blocks = parse_graph_blocks(text)
        for (direction, body_lines) in blocks:
            if not have_dir:
                merged.direction = direction
                have_dir = True

            # First pass: collect nodes
            for ln in body_lines:
                nid, label = parse_label_from_node_line(ln)
                if nid and label:
                    merged.ensure_node(label, prefer_id=nid)

            # Build reverse map for this block
            block_id2label: Dict[str, str] = {}
            for ln in body_lines:
                nid, label = parse_label_from_node_line(ln)
                if nid and label:
                    merged.ensure_node(label, prefer_id=nid)
                    block_id2label[nid] = label

            # Edges
            for ln in body_lines:
                md = DIRECTED_WITH_LABEL.match(ln)
                if md:
                    s_id, e_lbl, d_id = md.group('src'), (md.group('label') or '').strip(), md.group('dst')
                    s_label = block_id2label.get(s_id) or merged.id_to_label.get(s_id)
                    d_label = block_id2label.get(d_id) or merged.id_to_label.get(d_id)
                    if s_label and d_label:
                        merged.add_directed_edge(s_label, d_label, e_lbl)
                    continue

                mu = UNDIRECTED_EDGE_RE.match(ln)
                if mu:
                    s_id, d_id = mu.group('src'), mu.group('dst')
                    s_label = block_id2label.get(s_id) or merged.id_to_label.get(s_id)
                    d_label = block_id2label.get(d_id) or merged.id_to_label.get(d_id)
                    if s_label and d_label:
                        merged.add_undirected_edge(s_label, d_label)
                    continue

                ms = DIRECTED_EDGE_RE.match(ln)
                if ms:
                    s_id, d_id = ms.group('src'), ms.group('dst')
                    s_label = block_id2label.get(s_id) or merged.id_to_label.get(s_id)
                    d_label = block_id2label.get(d_id) or merged.id_to_label.get(d_id)
                    if s_label and d_label:
                        merged.add_directed_edge(s_label, d_label)

    return merged


def render_graph(g: Graph) -> str:
    out = []
    out.append(f"graph {g.direction}")
    for label in g.seen_label_order:
        node_id = g.label_to_id[label]
        esc = label.replace('"', r'\"')
        out.append(f'  {node_id}["{esc}"]')

    def edge_key(e):
        s, arrow, lbl, d = e
        return (s, arrow, lbl, d)

    for (src_label, arrow, edge_label, dst_label) in sorted(g.edges, key=edge_key):
        src_id = g.label_to_id[src_label]
        dst_id = g.label_to_id[dst_label]
        if arrow == '-->':
            if edge_label:
                esc = edge_label.replace('"', r'\"')
                out.append(f'  {src_id} -- "{esc}" --> {dst_id}')
            else:
                out.append(f'  {src_id} --> {dst_id}')
        elif arrow == '---':
            out.append(f'  {src_id} --- {dst_id}')
        else:
            out.append(f'  {src_id} --> {dst_id}')
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Merge multiple Mermaid (.mmd) graphs by node label.")
    parser.add_argument("inputs", nargs="+", help="Input .mmd files")
    parser.add_argument("-o", "--output", help="Output .mmd file (default: stdout)")
    args = parser.parse_args(argv)

    paths = [Path(x) for x in args.inputs]
    for p in paths:
        if not p.exists():
            parser.error(f"Input not found: {p}")

    merged = merge_files(paths)
    rendered = render_graph(merged)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
