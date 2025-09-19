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
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.symbol import RefType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtil
from utils import find_returns 
from graphviz import Digraph
from typing import List, Dict
from ghidra.program.database import ProgramDB
from ghidra.program.database.function import FunctionDB
from ghidra.app.decompiler import DecompileResults
import logging

from libc_funcs import libc_funcs

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

def is_libc(fname):
    return fname in libc_funcs

def is_gp(fname):
    return fname.startswith("TEE_") and not fname.startswith("TEE_SE")

def get_inline(inline, addr):
    for _, entry in inline.items():
        if inline['addr'] == int(inline):
            return entry
    return None

def is_api_call(target, tee, inline_funcs):
    program = getCurrentProgram()
    fm = program.getFunctionManager()
    f = fm.getFunctionAt(target)
    fname = f.getName()
    if is_gp(fname):
        return True
    if is_libc(fname):
        return True
    if fname.startswith("qsee_"):
        return True
    if f.isExternal():
        return True 
    if get_inline(inline_funcs, target) is not None:
        return True
    return False            
    
def api_type(target, tee, inline_funcs):
    program = getCurrentProgram()
    fm = program.getFunctionManager()
    f = fm.getFunctionAt(target)
    if is_gp(fname):
        return "gp_api"
    if is_libc(fname):
        return "libc"
    if fname.startswith("qsee_"):
        return "tee"
    if f.isExternal():
        return "tee"        
    inline_entry = get_inline(inline, target)    
    if inline_entry is not None:
        return inline_entry["type"]
    return "tee"
    
ta_fw = ["TA_CreateEntryPoint", "TA_OpenSessionEntryPoint", "TA_InvokeCommandEntryPoint", "TA_CloseSessionEntryPoint", "TA_DestroyEntryPoint"]

def gen_cfg(func, func_cfgs, tee, inline_funcs):
    monitor = ConsoleTaskMonitor()
    program = getCurrentProgram()
    fm = program.getFunctionManager()
    functions = fm.getFunctions(True)
    addressFactory = program.getAddressFactory()
    print('analyzing', func)
    try:
        ghidra_func = getGlobalFunctions(func)[0]
    except:
        #func_addr = addressFactory.getAddress(func)
        ghidra_func = fm.getFunctionAt(func)
    if not ghidra_func:
        return None, []
    block_model = BasicBlockModel(program)
    blocks_iter = block_model.getCodeBlocksContaining(ghidra_func.getBody(), monitor)

    funcs_todo = []        
    bb_map = {}   # addr_str -> BB info
    addr_to_name = {}  # entry address -> BB_x name
    bb_index = 0
    while blocks_iter.hasNext():
        block = blocks_iter.next()
        start = block.getFirstStartAddress()
        end = block.getMaxAddress()

        bb_name = "BB_{}".format(bb_index)
        bb_index += 1
        addr_to_name[str(start)] = bb_name

        # Calls and SVCs inside block
        calls = []
        svcs = []
        instr_iter = program.getListing().getInstructions(block, True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            # Detect calls
            if instr.getFlowType().isCall():
                for ref in instr.getReferencesFrom():
                    if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL or ref.getReferenceType().isCall():
                        target = ref.getToAddress()
                        is_api = is_api_call(target, tee, inline_funcs)
                        f = getFunctionAt(target)
                        if f:
                            calls.append({"func": f.getName(), "api": is_api})
                        else:
                            calls.append({"func": str(target), "api": is_api})
                        if not is_api and target not in func_cfgs and target not in funcs_todo:
                            funcs_todo.append(target)
                            
            # Detect svc instruction (ARM/Thumb)
            if instr.getMnemonicString().lower() == "svc":
                svcs.append(str(instr.getAddress()))

        bb_map[str(start)] = {
            "name": str(func),
            "start": str(start),
            "end": str(end),
            "calls": calls,
            "svc": svcs,
            "edges": []  # will fill later
        }

    # Second pass: resolve CFG edges
    for addr_str, bb in bb_map.items():
        block = block_model.getCodeBlockAt(toAddr(addr_str), monitor)
        if not block:
            continue
        dest_iter = block.getDestinations(monitor)
        while dest_iter.hasNext():
            edge = dest_iter.next()
            dest_addr = str(edge.getDestinationBlock().getFirstStartAddress())
            if dest_addr in bb_map:
                bb["edges"].append(bb_map[dest_addr]["name"])

    graph_json = {
        "function": func,
        "nodes": list(bb_map.values())
    }    
    return graph_json, funcs_todo

def do_work(tee, ta_json):
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
        + "cfg bbs analyzing: "
        + filename
        + 8 * "="
    )
    func_cfgs = {}
    func_todo = []
    ta_info = json.load(open(ta_json))
    if "inline" in ta_info:
        inline_funcs = ta_info["inline"]
    else:
        inline_funcs = {}
    for ta_f in ta_fw:
        func_todo.append(addressFactory.getAddress(hex(ta_info[ta_f+'_start'])))
    while(len(func_todo) != 0):
        func_todo_tmp = []
        for f in func_todo:
            cfg, todo = gen_cfg(f, func_cfgs, tee, inline_funcs)
            if cfg is None:
                continue
            func_cfgs[str(f)] = cfg
            for f_todo in todo:
                if f_todo not in func_todo:
                    func_todo_tmp.append(f_todo)
        func_todo = func_todo_tmp

    return func_cfgs
    
def main():
    logging.info("Initializing...")
    # create a target-specific output directory

    arg_parser = ArgumentParser(
        description="ghidra analyzer to find GP funcs for mitee", prog="script", prefix_chars="+")
    arg_parser.add_argument(
        "++tee",
        required=True,
        help="target TEE",
    )
    args = arg_parser.parse_args(args=getScriptArgs())
    prog_path = getCurrentProgram().getExecutablePath()
    ta_json = prog_path[:-3] + ".json"
    out_dir = os.path.join(os.path.dirname(prog_path), 'bbs')
    out_path = os.path.join(out_dir, 'bb_' + os.path.basename(prog_path)+'.json')
    if not os.path.exists(out_dir):
        os.system(f'mkdir -p {out_dir}')
        os.system(f'chmod 777 {out_dir}')
        
    out = do_work(args.tee, ta_json)
    open(out_path, "w").write(json.dumps(out, indent=4))
    os.system(f'chmod 666 {out_path}')
    return

if __name__ == "__main__":
    main()
