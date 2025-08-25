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
logging.basicConfig(
    format=FORMAT, datefmt="%Y-%m-%d:%H:%M:%S", level=logging.DEBUG
)
log = logging.getLogger(__name__)

################################################################################
# GLOBALS
################################################################################

DATA_BASE_DIR = "/data"
PROGRAM: ProgramDB = getCurrentProgram()
DECOMPILER: Decompiler = Decompiler(PROGRAM)
SIG_CHANGER = SignatureChanger(PROGRAM)

################################################################################
# CODE
################################################################################

def beanpod_find_GP():
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
    print(
    8 * "*"
    + "beanpod finder analyzing: "
    + filename
    + 8 * "="
    )
    out = { 
    }
    funcs = ["TA_InvokeCommandEntryPoint",  "TA_CreateEntryPoint",  "TA_OpenSessionEntryPoint", "TA_CloseSessionEntryPoint", "TA_DestroyEntryPoint"]
    for func in funcs:
        ghidra_func = getGlobalFunctions(func)[0]
        returns = find_returns(ghidra_func, is_thumb=True)
        out[f'{func}_start'] = ghidra_func.getEntryPoint().getOffset()
        out[f'{func}_end'] = returns 

    return out

def main():
	logging.info("Initializing...")
	# create a target-specific output directory

	arg_parser = ArgumentParser(
	description="ghidra analyzer to find GP funcs for beanpod", prog="script", prefix_chars="+")
	args = arg_parser.parse_args(args=getScriptArgs())
	prog_path = getCurrentProgram().getExecutablePath()
	out_path = prog_path[:-3] + ".json"

	out = beanpod_find_GP()
	open(out_path, "w").write(json.dumps(out, indent=4))
	os.system(f'chmod 666 {out_path}')
	return

if __name__ == "__main__":
    main()
