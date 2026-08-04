"""Basic-block CFGs of a TA, used as the denominator for coverage figures.

The paper estimates the maximally reachable number of basic blocks by building
a CFG from each TA and counting the basic blocks reachable from
TA_InvokeCommandEntryPoint (Section IV, Figure 4). The per-TA CFG data is
shipped with the artifact in <tee>/tas/bbs/bb_<ta>.json (produced by the
Ghidra headless scripts in ghidra/, see ghidra/analyze-bbs.sh).

This module re-implements eval/graphs/bb.py:cfg_ta() with a plain BFS instead
of networkx so the figures can be regenerated without extra dependencies.
"""

import json
import os

TA_ENTRIES = [
    "TA_CreateEntryPoint",
    "TA_OpenSessionEntryPoint",
    "TA_InvokeCommandEntryPoint",
    "TA_CloseSessionEntryPoint",
    "TA_DestroyEntryPoint",
]


def _hex8(n):
    return f"{n:08x}"


def bb_json_path(ta_path):
    ta_dir = os.path.dirname(os.path.realpath(ta_path))
    ta_name = os.path.basename(os.path.realpath(ta_path))
    return os.path.join(ta_dir, "bbs", "bb_" + ta_name + ".json")


def has_cfg(ta_path):
    return os.path.exists(bb_json_path(ta_path))


def build_cfg(ta_path):
    """Return (edges, bb_starts) where edges maps node -> set(nodes).

    Nodes are either function labels ("0002ab10") or basic-block start
    addresses in the same 8-hex-digit form. Inter-procedural edges are added
    for every non-API call, intra-procedural edges from the block's edges.
    """
    ta_real = os.path.realpath(ta_path)
    bb_data = json.load(open(bb_json_path(ta_real)))
    edges = {}
    bbs = set()

    def add_edge(a, b):
        edges.setdefault(a, set()).add(b)
        edges.setdefault(b, set())

    for func, data in bb_data.items():
        f_l = _hex8(int(func, 16)) if func.startswith("0x") else func
        edges.setdefault(f_l, set())
        name2bb = {}
        for bb in data.get("nodes", []):
            bb_l = bb["start"]
            bbs.add(bb_l)
            edges.setdefault(bb_l, set())
            name2bb[bb["name"]] = bb_l
            for call in bb.get("calls", []):
                if not call.get("api"):
                    add_edge(bb_l, call["func"])
        # The function label itself reaches its first basic block.
        nodes = data.get("nodes", [])
        if nodes:
            add_edge(f_l, nodes[0]["start"])
        for bb in nodes:
            for e in bb.get("edges", []):
                if e in name2bb:
                    add_edge(bb["start"], name2bb[e])
    return edges, bbs


def entry_address(ta_path, entry="TA_InvokeCommandEntryPoint"):
    meta = json.load(open(os.path.realpath(ta_path)[: -len(".ta")] + ".json"))
    addr = meta.get(entry + "_start", -1)
    return None if addr in (-1, None) else _hex8(addr)


def reachable_bbs(ta_path, entry="TA_InvokeCommandEntryPoint"):
    """Number of basic blocks reachable from `entry` (0 if unavailable)."""
    if not has_cfg(ta_path):
        return 0
    try:
        edges, bbs = build_cfg(ta_path)
    except Exception:
        return 0
    start = entry_address(ta_path, entry)
    if start is None or start not in edges:
        return 0
    seen = {start}
    stack = [start]
    while stack:
        n = stack.pop()
        for m in edges.get(n, ()):
            if m not in seen:
                seen.add(m)
                stack.append(m)
    return len(seen & bbs)


def reachable_bb_set(ta_path, entry="TA_InvokeCommandEntryPoint"):
    if not has_cfg(ta_path):
        return set()
    edges, bbs = build_cfg(ta_path)
    start = entry_address(ta_path, entry)
    if start is None or start not in edges:
        return set()
    seen = {start}
    stack = [start]
    while stack:
        n = stack.pop()
        for m in edges.get(n, ()):
            if m not in seen:
                seen.add(m)
                stack.append(m)
    return seen & bbs
