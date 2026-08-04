"""Minimal drcov parser for the coverage files the emulator writes.

Each replayed seed produces a drcov log in <harness>/out/cov/<seed>.cov. Only
basic blocks belonging to the TA module are of interest; for the TEEs whose TAs
are loaded at a non-zero base (beanpod, t6) the module base has to be added.

Adapted from eval/graphs/common.py:parse_drcov().
"""

REBASE_TEES = ("beanpod", "t6")


def parse(path, tee):
    """Return the set of TA-relative basic block start addresses in a .cov."""
    try:
        raw = open(path, "rb").read()
    except OSError:
        return set()
    if b"BB Table: " not in raw:
        return set()

    ta_id = None
    base = 0
    module_table = raw.split(b"timestamp, path\n")[-1]
    for line in module_table.split(b"\n"):
        if b"emulator/rootfs" in line and b".ta" in line:
            parts = line.split(b",")
            try:
                ta_id = int(parts[0])
                base = int(parts[1])
            except (ValueError, IndexError):
                continue
            break
    if ta_id is None:
        return set()

    try:
        nr_bbs = int(raw.split(b"BB Table: ")[-1].split(b"bbs\n")[0].decode())
    except ValueError:
        return set()
    blob = raw.split(b"bbs\n")[-1]

    out = set()
    off = 0
    for _ in range(nr_bbs):
        chunk = blob[off:off + 8]
        if len(chunk) < 8:
            break
        start = int.from_bytes(chunk[0:4], "little")
        mod_id = int.from_bytes(chunk[6:8], "little")
        if mod_id == ta_id:
            if tee in REBASE_TEES:
                start += base
            out.add(f"{start:08x}")
        off += 8
    return out


def seed_time(cov_name):
    """Seconds into the campaign at which AFL saved this queue entry."""
    if "time:" not in cov_name:
        return 0
    try:
        return int(cov_name.split("time:")[-1].split(",")[0]) // 1000
    except ValueError:
        return 0
