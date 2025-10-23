import os
import json
from argparse import ArgumentParser
from decompile_util import (
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

FORMAT = "%(asctime)s,%(msecs)d %(levelname)-8s " "%(message)s"
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


def t6_find_GP():
    print("working..")
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
    print(8 * "*" + "t6 finder analyzing: " + filename + 8 * "=")
    out = {"inline": {}}
    for string in DefinedDataIterator.definedStrings(program):
        for ref in XReferenceUtil.getXRefList(string):
            symbol = string.toString().split('ds "')[-1]
            symbol = symbol[:-1]
            if symbol.startswith("TEE_"):
                symbol = symbol.split(" ")[0]
                if symbol.endswith(":"):
                    symbol = symbol[:-1]
                if symbol.endswith("1"):
                    symbol = symbol[:-1]
                print("found GP function", string, ref)
                gp_function = functionManager.getFunctionContaining(ref)
                if gp_function is not None:
                    print(
                        f"adding function {symbol} at {hex(gp_function.getEntryPoint().getOffset())}"
                    )
                    out["inline"][symbol] = {
                        "addr": gp_function.getEntryPoint().getOffset(),
                        "type": "gp_api",
                    }
            if symbol.startswith("TA_"):
                print("found GP lifecycle function", string, ref)
                gp_function = functionManager.getFunctionContaining(ref)
                if gp_function is not None:
                    print(
                        f"adding function {symbol} at {hex(gp_function.getEntryPoint().getOffset())}"
                    )
                    out[f"{symbol}_start"] = gp_function.getEntryPoint().getOffset()
                    returns = find_returns(gp_function, is_thumb=True)
                    out[f"{symbol}_end"] = returns

    out["TA_CloseSessionEntryPoint_start"] = -1
    out["TA_CloseSessionEntryPoint_end"] = [-1]
    out["TA_DestroyEntryPoint_start"] = -1
    out["TA_DestroyEntryPoint_end"] = [-1]

    return out


def main():
    logging.info("Initializing...")
    # create a target-specific output directory

    arg_parser = ArgumentParser(
        description="ghidra analyzer to find GP funcs for mitee",
        prog="script",
        prefix_chars="+",
    )
    args = arg_parser.parse_args(args=getScriptArgs())
    prog_path = getCurrentProgram().getExecutablePath()
    out_path = prog_path[:-3] + ".json"

    out = t6_find_GP()
    open(out_path, "w").write(json.dumps(out, indent=4))
    os.system(f"chmod 666 {out_path}")
    return


if __name__ == "__main__":
    main()
