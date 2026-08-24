import json
import logging
import os
from argparse import ArgumentParser
from pathlib import Path

import yaml
from ghidra.app.decompiler import DecompInterface
from ghidra.program.database import ProgramDB
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.symbol import RefType
from ghidra.util.task import ConsoleTaskMonitor

from decompile_util import Decompiler
from libc_funcs import libc_funcs

FORMAT = "%(asctime)s,%(msecs)d %(levelname)-8s " "%(message)s"
logging.basicConfig(format=FORMAT, datefmt="%Y-%m-%d:%H:%M:%S", level=logging.DEBUG)
log = logging.getLogger(__name__)
VERBOSE = os.environ.get("BBS_VERBOSE", "0") == "1"

PROGRAM: ProgramDB = getCurrentProgram()
DECOMPILER: Decompiler = Decompiler(PROGRAM)
QSEE_NONGP_CLASSIFIER_PATH = Path("/src/qsee_nongp_api_classification.yml")

try:
    INTEGER_TYPES = (int, long)
except NameError:
    INTEGER_TYPES = (int,)


def trace(*args):
    if VERBOSE:
        print(*args)


def normalize_address(value):
    if hasattr(value, "getOffset"):
        offset = value.getOffset()
    elif isinstance(value, INTEGER_TYPES):
        offset = value
    else:
        text = str(value).strip()
        if text.startswith("Stack"):
            return text
        try:
            offset = int(text, 16)
        except ValueError:
            return text
    width = 16 if offset > 0xFFFFFFFF else 8
    return ("%0*x" % (width, offset)).lower()


def convert(inline_funcs):
    out = {}
    for func_name, entry in inline_funcs.items():
        out[entry["addr"]] = {"name": func_name, "type": entry["type"]}
    return out


def is_libc(fname):
    return fname in libc_funcs


def is_gp(fname, tee=None):
    if tee == "qsee_nongp":
        return False
    return (
        fname.startswith("TEE_")
        and not fname.startswith("TEE_SE")
        and not fname.startswith("TEE_Rpmb")
    )


def get_inline(inline_funcs, addr):
    if addr.getOffset() in inline_funcs:
        return inline_funcs[addr.getOffset()]
    return None


def is_function_stub_name(fname):
    return fname.startswith("FUN_") or fname.startswith("thunk_FUN_")


def is_gp_std(fname, tee=None):
    if tee == "qsee_nongp":
        return False
    return (
        fname.startswith("TEE_LogPrint")
        or fname == "msee_ta_printf_va"
        or fname == "TEES_IsREESharedMemory"
    )


def is_complex_interaction(fname):
    return fname in {"ioctl", "TEE_InvokeTACommand", "read", "write"}


def load_qsee_classification():
    if not QSEE_NONGP_CLASSIFIER_PATH.exists():
        return {"exact": {}, "prefix": [], "defaults": {}}

    raw = yaml.safe_load(QSEE_NONGP_CLASSIFIER_PATH.read_text()) or {}
    prefix_rules = []
    for prefix, rule in (raw.get("prefix", {}) or {}).items():
        normalized = dict(rule or {})
        normalized["prefix"] = prefix
        normalized.setdefault("traits", [])
        prefix_rules.append(normalized)

    exact_rules = {}
    for name, rule in (raw.get("exact", {}) or {}).items():
        normalized = dict(rule or {})
        normalized.setdefault("traits", [])
        exact_rules[name] = normalized

    defaults = dict(raw.get("defaults", {}) or {})
    defaults.setdefault("traits", [])

    return {
        "exact": exact_rules,
        "prefix": prefix_rules,
        "defaults": defaults,
    }


def resolve_qsee_rule(fname, rules):
    if fname in rules["exact"]:
        return dict(rules["exact"][fname]), "exact"
    for rule in rules["prefix"]:
        if fname.startswith(rule["prefix"]):
            match = dict(rule)
            match.pop("prefix", None)
            return match, "prefix"
    return None, None


def normalize_traits(rule):
    traits = rule.get("traits", [])
    return [trait for trait in traits if trait]


def build_call_record(
    func_name,
    target,
    api,
    api_type,
    *,
    family=None,
    traits=None,
    name_source="function",
):
    target_addr = normalize_address(target)
    record = {
        "func": func_name,
        "api": api,
        "api_type": api_type,
    }
    if family is not None:
        record["family"] = family
    if traits is not None:
        record["traits"] = list(traits)
    if func_name != target_addr:
        record["target_addr"] = target_addr
    if name_source and name_source != "function":
        record["name_source"] = name_source
    return record


def classify_qsee_call(body, target, inline_funcs, rules):
    inline_entry = get_inline(inline_funcs, target)
    if inline_entry is not None:
        return build_call_record(
            inline_entry["name"],
            target,
            True,
            inline_entry["type"],
            family=inline_entry["type"],
            name_source="inline",
        ), False, False

    if body.contains(target):
        return build_call_record(
            normalize_address(target),
            target,
            False,
            None,
            family="internal",
            traits=["intra_body"],
            name_source="recovered",
        ), False, True

    program = getCurrentProgram()
    function_manager = program.getFunctionManager()
    ghidra_func = function_manager.getFunctionAt(target)
    if ghidra_func is None:
        ghidra_func = function_manager.getFunctionContaining(target)

    func_name = normalize_address(target)
    name_source = "unknown"
    if ghidra_func is not None:
        func_name = ghidra_func.getName()
        name_source = "external" if ghidra_func.isExternal() else "function"
        if is_function_stub_name(func_name):
            func_name = normalize_address(target)
            name_source = "recovered"

    if is_libc(func_name):
        return build_call_record(
            func_name,
            target,
            True,
            "libc",
            family="libc",
            traits=[],
            name_source=name_source,
        ), False, False

    rule, _ = resolve_qsee_rule(func_name, rules)
    if rule is not None:
        return build_call_record(
            func_name,
            target,
            True,
            rule["api_type"],
            family=rule.get("family", rule["api_type"]),
            traits=normalize_traits(rule),
            name_source=name_source,
        ), False, False

    if ghidra_func is not None and not ghidra_func.isExternal():
        return build_call_record(
            func_name,
            target,
            False,
            None,
            family="internal",
            traits=[],
            name_source=name_source,
        ), False, True

    fallback = dict(rules.get("defaults", {}))
    fallback.setdefault("api_type", "tee_unknown")
    fallback.setdefault("family", "unknown_external")
    traits = normalize_traits(fallback)
    if "unresolved" not in traits and func_name == normalize_address(target):
        traits.append("unresolved")
    return build_call_record(
        func_name,
        target,
        True,
        fallback["api_type"],
        family=fallback["family"],
        traits=traits,
        name_source=name_source,
    ), False, False


def classify_generic_call(body, target, tee, inline_funcs):
    inline_entry = get_inline(inline_funcs, target)
    if inline_entry is not None:
        return build_call_record(
            inline_entry["name"],
            target,
            True,
            inline_entry["type"],
            family=inline_entry["type"],
            name_source="inline",
        ), False, False

    if body.contains(target):
        return build_call_record(
            normalize_address(target),
            target,
            False,
            None,
            family="internal",
            traits=["intra_body"],
            name_source="recovered",
        ), False, True

    program = getCurrentProgram()
    function_manager = program.getFunctionManager()
    ghidra_func = function_manager.getFunctionContaining(target)

    if ghidra_func is None:
        if target.getOffset() > 0xFFFFFFFF:
            return None, False, False
        return build_call_record(
            normalize_address(target),
            target,
            True,
            "tee",
            family="tee",
            traits=["unresolved"],
            name_source="unknown",
        ), False, False

    func_name = ghidra_func.getName()
    if is_gp(func_name, tee):
        return build_call_record(
            func_name,
            target,
            True,
            "gp_api",
            family="gp_api",
            name_source="function",
        ), False, False
    if is_libc(func_name):
        return build_call_record(
            func_name,
            target,
            True,
            "libc",
            family="libc",
            name_source="function",
        ), False, False
    if func_name.startswith("fdio_"):
        return build_call_record(
            func_name,
            target,
            True,
            "tee",
            family="fdio",
            name_source="function",
        ), False, False
    if func_name.startswith("qsee_"):
        return build_call_record(
            func_name,
            target,
            True,
            "tee",
            family="qsee",
            name_source="function",
        ), False, False
    if is_complex_interaction(func_name):
        return build_call_record(
            func_name,
            target,
            True,
            "tee",
            family="interaction",
            name_source="function",
        ), False, False
    if is_gp_std(func_name, tee):
        return build_call_record(
            func_name,
            target,
            True,
            "tee_std",
            family="tee_std",
            name_source="function",
        ), False, False
    if ghidra_func.isExternal():
        return build_call_record(
            func_name,
            target,
            True,
            "tee",
            family="tee",
            name_source="external",
        ), False, False

    if is_function_stub_name(func_name):
        func_name = normalize_address(target)

    return build_call_record(
        func_name,
        target,
        False,
        None,
        family="internal",
        name_source="function",
    ), False, True


def classify_call(body, target, tee, inline_funcs, qsee_rules):
    if tee == "qsee_nongp":
        return classify_qsee_call(body, target, inline_funcs, qsee_rules)
    return classify_generic_call(body, target, tee, inline_funcs)


def is_call(ghidra_func, instr):
    flow_type = instr.getFlowType()
    if flow_type.isCall():
        return True
    if flow_type.isConditional() or flow_type.isUnConditional() or flow_type.isJump():
        for ref in instr.getReferencesFrom():
            target = ref.getToAddress()
            if str(target).startswith("Stack"):
                continue
            if not ghidra_func.getBody().contains(target):
                return True
    return False


def load_ta_info(ta_path: Path):
    yml_path = ta_path.with_suffix(".yml")
    if yml_path.exists():
        with yml_path.open("r") as handle:
            yml_info = yaml.safe_load(handle)
        ta_info = {}
        for key, value in yml_info.items():
            if not isinstance(value, dict):
                continue
            if not {"start", "end"} <= set(value):
                continue
            ta_info["%s_start" % key] = value["start"]
            ta_info["%s_end" % key] = value["end"]
        return ta_info

    json_path = ta_path.with_suffix(".json")
    if not json_path.exists():
        raise FileNotFoundError("JSON/YAML file for %s not found" % ta_path)
    return json.loads(json_path.read_text())


def get_entry_addrs(ta_info, tee):
    out = []
    for key, value in ta_info.items():
        if not key.endswith("_start"):
            continue
        if not isinstance(value, int):
            continue
        if value == -1:
            continue
        out.append(value)
    if tee == "qsee_nongp" and "CElfFile_invoke_start" in ta_info:
        root_value = ta_info["CElfFile_invoke_start"]
        ordered = [root_value]
        ordered.extend(value for value in out if value != root_value)
        return ordered
    return out


def gen_cfg(func, seen_funcs, tee, inline_funcs, qsee_rules):
    monitor = ConsoleTaskMonitor()
    program = getCurrentProgram()
    function_manager = program.getFunctionManager()
    address_factory = program.getAddressFactory()
    trace("analyzing", func)

    try:
        ghidra_func = getGlobalFunctions(func)[0]
    except Exception:
        ghidra_func = function_manager.getFunctionAt(address_factory.getAddress(func))

    if not ghidra_func:
        clearListing(address_factory.getAddress(func))
        disassemble(address_factory.getAddress(func))
        ghidra_func = createFunction(address_factory.getAddress(func), None)
        if not ghidra_func:
            trace("could not create function", func)
            return None, []

    block_model = BasicBlockModel(program)
    blocks_iter = block_model.getCodeBlocksContaining(ghidra_func.getBody(), monitor)

    funcs_todo = []
    bb_map = {}
    addr_to_name = {}
    bb_index = 0
    while blocks_iter.hasNext():
        block = blocks_iter.next()
        start = block.getFirstStartAddress()
        end = block.getMaxAddress()
        start_key = normalize_address(start)
        end_key = normalize_address(end)

        bb_name = "BB_%d" % bb_index
        bb_index += 1
        addr_to_name[start_key] = bb_name

        calls = []
        svcs = []
        instr_iter = program.getListing().getInstructions(block, True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            if is_call(ghidra_func, instr):
                for ref in instr.getReferencesFrom():
                    ref_type = ref.getReferenceType()
                    if ref_type.isRead() or ref_type.isData():
                        continue
                    if not (
                        ref_type == RefType.UNCONDITIONAL_CALL
                        or ref_type.isCall()
                        or ref_type.isComputed()
                        or ref_type.isConditional()
                        or ref_type.isJump()
                    ):
                        continue

                    target = ref.getToAddress()
                    if str(target).startswith("Stack"):
                        continue

                    call_record, skip_emit, should_recurse = classify_call(
                        ghidra_func.getBody(), target, tee, inline_funcs, qsee_rules
                    )
                    if should_recurse:
                        target_key = normalize_address(target)
                        if target_key not in seen_funcs and target_key not in funcs_todo:
                            funcs_todo.append(target_key)
                    if call_record is None or skip_emit:
                        continue

                    if tee == "mitee" and call_record["func"].startswith("zx_"):
                        svcs.append(normalize_address(instr.getAddress()))
                        continue

                    calls.append(call_record)

            mnemonic = instr.getMnemonicString().lower()
            if mnemonic == "svc" or mnemonic == "swi":
                svcs.append(normalize_address(instr.getAddress()))

        bb_map[start_key] = {
            "name": bb_name,
            "start": start_key,
            "end": end_key,
            "calls": calls,
            "svc": svcs,
            "edges": [],
        }

    for addr_str, bb in bb_map.items():
        block = block_model.getCodeBlockAt(toAddr(addr_str), monitor)
        if not block:
            continue
        dest_iter = block.getDestinations(monitor)
        while dest_iter.hasNext():
            edge = dest_iter.next()
            dest_addr = normalize_address(edge.getDestinationBlock().getFirstStartAddress())
            if dest_addr in bb_map:
                bb["edges"].append(bb_map[dest_addr]["name"])

    return {"function": normalize_address(func), "nodes": list(bb_map.values())}, funcs_todo


def iter_cfgs(tee, ta_bin_path):
    program = getCurrentProgram()
    decompinterface = DecompInterface()
    decompinterface.openProgram(program)
    address_factory = program.getAddressFactory()
    image_base = program.getImageBase()
    if image_base == address_factory.getAddress("0x100000"):
        program.setImageBase(address_factory.getAddress("0x0"), True)

    ta_info = load_ta_info(ta_bin_path)
    if "inline" in ta_info:
        inline_funcs = convert(ta_info["inline"])
    else:
        inline_funcs = {}

    qsee_rules = load_qsee_classification() if tee == "qsee_nongp" else None
    seen_funcs = set()
    func_todo = [normalize_address(addr) for addr in get_entry_addrs(ta_info, tee)]

    while func_todo:
        next_todo = []
        for func in sorted(set(func_todo)):
            if func in seen_funcs:
                continue
            cfg, todo = gen_cfg(func, seen_funcs, tee, inline_funcs, qsee_rules)
            seen_funcs.add(normalize_address(func))
            if cfg is None:
                continue
            yield normalize_address(func), cfg
            for func_todo_entry in todo:
                if (
                    func_todo_entry not in seen_funcs
                    and func_todo_entry not in next_todo
                ):
                    next_todo.append(func_todo_entry)
        func_todo = next_todo


def write_cfg_json(out_path, cfg_iter):
    with out_path.open("w") as handle:
        handle.write("{\n")
        is_first = True
        for func_name, cfg in cfg_iter:
            if not is_first:
                handle.write(",\n")
            is_first = False
            handle.write("%s: %s" % (json.dumps(func_name), json.dumps(cfg)))
        handle.write("\n}\n")


def main():
    logging.info("Initializing...")
    arg_parser = ArgumentParser(
        description="ghidra analyzer to build BB CFGs",
        prog="script",
        prefix_chars="+",
    )
    arg_parser.add_argument("++tee", required=True, help="target TEE")
    args = arg_parser.parse_args(args=getScriptArgs())

    program = getCurrentProgram()
    prog_path = Path(program.getExecutablePath())
    if not prog_path.exists():
        prog_path_str = prog_path.as_posix()
        prog_path = Path("/mnt") / prog_path_str[prog_path_str.find(args.tee) :]

    out_dir = prog_path.parent / "bbs"
    out_path = out_dir / ("bb_%s.json" % prog_path.name)
    if not out_dir.exists():
        out_dir.mkdir(parents=True, exist_ok=True)
        os.system("chmod 777 %s" % out_dir.as_posix())

    cfg_iter = iter_cfgs(args.tee, prog_path)
    write_cfg_json(out_path, cfg_iter)
    os.system("chmod 666 %s" % out_path)
    print("wrote %s" % out_path)


if __name__ == "__main__":
    main()
