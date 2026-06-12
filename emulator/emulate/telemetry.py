"""Unmodeled-API telemetry.

Every hooked symbol the emulator doesn't implement resolves to the no-op
`gp_api.default_func` (see emulator_no_loader.get_api_impl). A stub that silently
returns can BOTH hide a real bug (the TA gets a benign zero where the device
returns attacker-influenced data) AND fabricate an emulator-only crash (the TA
dereferences an out-pointer the stub never filled). So when triaging a finding
you want to know: did this execution flow through any stub?

This records the stubbed symbols hit during a run (always-on, cheap). It is
dumped next to the drcov coverage on replay (`<cov>.unmodeled`) -- exactly the
triage context -- and via atexit when TAEMU_TELEMETRY=<path> is set.
"""
import os
import atexit
from collections import Counter

_counts = Counter()
_DUMP_PATH = os.environ.get("TAEMU_TELEMETRY", "")


def record(name):
    """Note that `name` fell through to default_func. Cheap; always on."""
    _counts[name] += 1


def summary():
    return dict(_counts)


def reset():
    _counts.clear()


def dump(path):
    """Write the unmodeled-API tally to `path` (skips if nothing was stubbed)."""
    if not _counts:
        return
    try:
        with open(path, "w") as f:
            f.write("# count\tunmodeled API (fell through to default_func)\n")
            for name, n in _counts.most_common():
                f.write(f"{n}\t{name}\n")
    except OSError:
        pass


@atexit.register
def _atexit_dump():
    if _DUMP_PATH:
        dump(_DUMP_PATH)
