"""Guards for the call-signature and TEE-detection bugs found on main.

Both classes of bug shipped: a call site whose arity did not match the callee
(free_core, crash, read_c_str) and a TEE detection rule that routed GP QSEE TAs
to the non-GP loader. Neither shows up until a TA exercises that exact path, so
pin them here.
"""
import ast
import json
import os

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
EMU = os.path.join(REPO, "emulator", "emulate")

# Dead code: nothing imports it, and its calls target a long-gone 2-arg API.
SKIP = {os.path.join(EMU, "custom", "ut_pf_cp.py")}


def _walk_py():
    for root, dirs, files in os.walk(EMU):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", "tests")]
        for fn in files:
            if fn.endswith(".py"):
                p = os.path.join(root, fn)
                if p not in SKIP:
                    yield p


def _module_file(mod, from_file, level):
    """Resolve an import target to a file under emulate/, or None if external."""
    if level:                                   # relative: .gp.utils.err
        base = os.path.dirname(from_file)
        for _ in range(level - 1):
            base = os.path.dirname(base)
        parts = mod.split(".") if mod else []
    elif mod.startswith("emulate."):
        base, parts = os.path.dirname(EMU), mod.split(".")
    else:
        return None                             # pwn, ctypes, qiling, ...
    cand = os.path.join(base, *parts)
    for c in (cand + ".py", os.path.join(cand, "__init__.py")):
        if os.path.isfile(c):
            return c
    return None


def _bound_names(path, _seen=None):
    """Top-level names a module binds, following internal star-imports once."""
    _seen = _seen or set()
    if path in _seen:
        return set()
    _seen.add(path)
    try:
        tree = ast.parse(open(path, errors="replace").read())
    except (SyntaxError, OSError):
        return set()
    names = set()
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(n.name)
        elif isinstance(n, ast.ImportFrom):
            for a in n.names:
                if a.name == "*":
                    tgt = _module_file(n.module or "", path, n.level)
                    if tgt:
                        names |= _bound_names(tgt, _seen)
                else:
                    names.add(a.asname or a.name)
        elif isinstance(n, ast.Import):
            for a in n.names:
                names.add((a.asname or a.name).split(".")[0])
    return names


def test_call_arity_matches_local_definitions():
    """No call site may pass too few/many args to a uniquely-defined local function.

    Files with a star-import are still checked: internal star-imports are
    resolved, and only names that could come from an *external* star-import
    (pwn, ctypes) are skipped. Without that, beanpod_api.py -- where the
    crash(ql. hook_data.func_name) typo lived -- would be exempt entirely.
    """
    sigs, calls = {}, []
    for p in _walk_py():
        try:
            tree = ast.parse(open(p, errors="replace").read())
        except SyntaxError:
            continue
        external_star = any(
            isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
            and _module_file(n.module or "", p, n.level) is None
            for n in ast.walk(tree))
        known = _bound_names(p) if external_star else None
        for n in ast.walk(tree):
            if isinstance(n, ast.FunctionDef):
                sigs.setdefault(n.name, []).append(
                    (len(n.args.args) - len(n.args.defaults), len(n.args.args),
                     bool(n.args.vararg or n.args.kwarg)))
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                # under an external star-import, only trust names we can account for
                if known is not None and n.func.id not in known:
                    continue
                calls.append((p, n.lineno, n.func.id, len(n.args), len(n.keywords)))

    bad = []
    for path, line, name, npos, nkw in calls:
        defs = sigs.get(name)
        if not defs or len(defs) != 1:
            continue                      # not local, or ambiguous
        req, total, star = defs[0]
        if star:
            continue
        if npos + nkw < req or npos > total:
            bad.append(f"{os.path.relpath(path, REPO)}:{line}: "
                       f"{name}({npos} args) but it takes {req}..{total}")
    assert not bad, "call-arity mismatches:\n  " + "\n  ".join(bad)


def test_qsee_metadata_routes_to_its_own_directory():
    """GP and non-GP QSEE TAs are told apart by their metadata, not by a string
    that both binaries contain (see __main__.py TEE detection)."""
    checked = 0
    for tee_dir, expected in (("qsee", "qsee"), ("qsee_nongp", "qsee_nongp")):
        tas = os.path.join(REPO, tee_dir, "tas")
        if not os.path.isdir(tas):
            continue
        for fn in sorted(os.listdir(tas)):
            if not fn.endswith(".json"):
                continue
            try:
                keys = set(json.load(open(os.path.join(tas, fn))))
            except (ValueError, OSError):
                continue
            if "TA_InvokeCommandEntryPoint_start" in keys:
                got = "qsee"
            elif "CElfFile_invoke_start" in keys:
                got = "qsee_nongp"
            else:
                continue                  # neither: not a loader-routing metadata file
            assert got == expected, f"{tee_dir}/tas/{fn}: metadata says {got}"
            checked += 1
    assert checked > 0, "no QSEE metadata found to check"
