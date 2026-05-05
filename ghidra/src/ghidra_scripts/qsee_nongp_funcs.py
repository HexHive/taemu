import os
import json
from argparse import ArgumentParser
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


def qsee_nongp_find_GP(program):
    print("working..")
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
    out = {}
    funcs = [
        "CElfFile_invoke",
    ]
    for func in funcs:
        ghidra_func = getGlobalFunctions(func)[0]
        ptrSize = program.getDefaultPointerSize()
        returns = find_returns(ghidra_func, is_thumb=ptrSize == 4, is_pie=True)
        if ptrSize == 4:
            out[f"{func}_start"] = ghidra_func.getEntryPoint().getOffset() - 0x10000
        else:
            out[f"{func}_start"] = ghidra_func.getEntryPoint().getOffset() - 0x100000
        out[f"{func}_end"] = returns

    return out

from pathlib import Path
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
    out_path = Path(program.getExecutablePath()).with_suffix(".json")

    out = qsee_nongp_find_GP(program)
    out_path.write_text(json.dumps(out, indent=4))
    out_path.with_suffix(".yml").write_text(f"""\
CElfFile_invoke:
  start: {out["CElfFile_invoke_start"]}
  end: [{", ".join(map(hex, out["CElfFile_invoke_end"]))}]
""")
    os.system(f"chmod 666 {out_path}")
    return


if __name__ == "__main__":
    main()
