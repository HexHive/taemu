import os
import json
from argparse import ArgumentParser
from decompile_util import (
    SignatureChanger,
    Decompiler,
    INVOKE_COMMAND_FUNC_NAME,
    OPEN_SESSION_FUNC_NAME,
)
from oppo_vivo_tainvokedetect import find_vivo_oppo_invokecmd
from gpdetect import detect_less_dumb
from mitee_gpdetect import find_mitee_invokecmd
import helpers
import time
import json
from tipianalyzer import (
    TypeCheckAnalyzer,
    MemrefAnalyzerReport,
    MemrefAnalyzerResult,
)
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtil

# from ghidra.program.model.listing import getCalledFunctions, getCallingFunctions



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

def find_returns(function, aarch64=True):
		# iterate over instructions in function, mark all rets	
		ret_offsets = []
		listing = getCurrentProgram().getListing()
		instructions = listing.getInstructions(function.getBody(), True)
		for instr in instructions:
				mnemonic = instr.getMnemonicString().upper()
				# Check for return instructions (RET)
				if mnemonic in ["RET", "RETN", "RETQ"] and aarch64:  # common mnemonics, adjust per architecture
						ret_offsets.append(instr.getAddress().getOffset()-0x100000)
		return ret_offsets

def mitee_find_GP():
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
		+ "mitee finder analyzing: "
		+ filename
		+ 8 * "="
	)
	out = { 
		"inline": {}
	}
	for string in DefinedDataIterator.definedStrings(program):
		for ref in XReferenceUtil.getXRefList(string):
			symbol = string.toString().split("ds \"")[-1]
			symbol = symbol[:-1]
			if symbol.startswith("TEE_"):
				if symbol.endswith("1"):
					symbol = symbol[:-1]
				print("found GP function", string, ref)
				gp_function = functionManager.getFunctionContaining(
					ref
				)
				print(f"adding function {symbol} at {hex(gp_function.getEntryPoint().getOffset())}")
				out["inline"][symbol] = {"addr": gp_function.getEntryPoint().getOffset()-0x100000, "type": "gp_api"}
			if symbol.startswith("TA_"):
				print("found GP lifecycle function", string, ref)
				gp_function = functionManager.getFunctionContaining(
					ref
				)
				print(f"adding function {symbol} at {hex(gp_function.getEntryPoint().getOffset())}")
				out[f'{symbol}_start'] = gp_function.getEntryPoint().getOffset()-0x100000
				returns = find_returns(gp_function, aarch64=True)
				out[f'{symbol}_end'] = returns
	return out

def main():
	logging.info("Initializing...")
	# create a target-specific output directory

	arg_parser = ArgumentParser(
	description="ghidra analyzer to find GP funcs for mitee", prog="script", prefix_chars="+")
	args = arg_parser.parse_args(args=getScriptArgs())
	prog_path = getCurrentProgram().getExecutablePath()
	out_path = prog_path[:-3] + ".json"

	out = mitee_find_GP()
	open(out_path, "w").write(json.dumps(out, indent=4))
	os.system(f'chmod 666 {out_path}')
	return

if __name__ == "__main__":
    main()
