import os
import json
from argparse import ArgumentParser
from pathlib import Path
from decompile_util import (
    SignatureChanger,
    Decompiler,
    INVOKE_COMMAND_FUNC_NAME,
    OPEN_SESSION_FUNC_NAME,
)
import helpers
import time
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtil
import yaml
from utils import find_returns

################################################################################
# TYPING
################################################################################

from typing import List, Dict
from ghidra.program.database import ProgramDB
from ghidra.program.database.function import FunctionDB
from ghidra.app.decompiler import DecompileResults

################################################################################
# LOGGING
################################################################################

import logging

FORMAT = "%(asctime)s,%(msecs)d %(levelname)-8s %(message)s"
logging.basicConfig(format=FORMAT, datefmt="%Y-%m-%d:%H:%M:%S", level=logging.DEBUG)
log = logging.getLogger(__name__)

################################################################################
# GLOBALS
################################################################################

DATA_BASE_DIR = "/data"
PROGRAM: ProgramDB = getCurrentProgram()
DECOMPILER: Decompiler = Decompiler(PROGRAM)

################################################################################
# CODE
################################################################################


def qsee_nongp_find_entrypoints():
    program = getCurrentProgram()
    monitor = ConsoleTaskMonitor()
    memory = program.getMemory()
    binaryPath = program.getExecutablePath()
    listing = program.getListing()
    filename = os.path.basename(binaryPath)
    decompinterface = DecompInterface()
    decompinterface.openProgram(program)
    functionManager = program.getFunctionManager()
    functions = functionManager.getFunctions(True)
    addressFactory = program.getAddressFactory()
    print(8 * "*" + "qsee_nongp finder analyzing: " + filename + 8 * "=")
    json_out = {}
    yaml_out = {}
    funcs = [
        "CElfFile_invoke",
        "command_handler",
        "setup_teardown",
        "tz_app_cmd_handler",
    ]
    for func in funcs:
        ghidra_func = getGlobalFunctions(func)[0]
        ptrSize = program.getDefaultPointerSize()
        returns = find_returns(ghidra_func, is_thumb=ptrSize == 4)
        if ptrSize == 4:
            raise Exception("Not supported. (Maybe)")
            start = ghidra_func.getEntryPoint().getOffset() - 0x10000
        else:
            start = ghidra_func.getEntryPoint().getOffset() & 0xFFFFF
        returns = [(x + 0x100000) & 0xFFFFF for x in returns]
        if any(x < 0 for x in (*returns, start)):
            raise Exception("Something is wrong with parsing.")
        json_out[f"{func}_start"] = start
        json_out[f"{func}_end"] = returns
        yaml_out[func] = {
            "start": start,
            "end": returns,
        }

    return json_out, yaml_out


def write_yaml_maybe(yaml_path, yaml_out):
    if yaml_path.exists():
        yaml_in = yaml.safe_load(yaml_path.read_text())
        # The things that are present in yaml_in, and arent the same in yaml_out, should raise exception
        # The things that match, should stay as is
        # The things that are present in yaml_out, and arent the same in yaml_in, should be added to yaml_out
        for key, value in yaml_out.items():
            if key not in yaml_in:
                yaml_in[key] = value
            else:
                if not isinstance(yaml_in[key], dict):
                    logging.warning("Key '%s' is not a dict in %s", key, yaml_path)
                if yaml_in[key] != value:
                    raise Exception(
                        f"Key {key} has different values. in: {yaml_in} out: {yaml_out}"
                    )
        yaml_out = yaml_in
    yaml_path.write_text(yaml.dump(yaml_out, indent=4))
    log.info("Wrote %s", yaml_path)
    yaml_path.chmod(0o666)


def main():
    logging.info("Initializing...")
    # create a target-specific output directory

    arg_parser = ArgumentParser(
        description="ghidra analyzer to find GP funcs for teegris",
        prog="script",
        prefix_chars="+",
    )
    args = arg_parser.parse_args(args=getScriptArgs())
    program = getCurrentProgram()
    ta_path = Path(program.getExecutablePath())
    json_path = ta_path.with_suffix(".json")
    yaml_path = ta_path.with_suffix(".yml")

    json_out, yaml_out = qsee_nongp_find_entrypoints()
    json_path.write_text(json.dumps(json_out, indent=4))
    log.info("Wrote %s", json_path)
    json_path.chmod(0o666)
    try:
        write_yaml_maybe(yaml_path, yaml_out)
    except Exception as e:
        logging.error("Error writing %s: %s", yaml_path, e)
        yaml_path.with_suffix(".1.yml").write_text(yaml.dump(yaml_out, indent=4))
    return


if __name__ == "__main__":
    main()
