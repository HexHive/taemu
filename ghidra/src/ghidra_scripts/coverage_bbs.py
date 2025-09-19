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
from ghidra.program.model.address import Address
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

def convert(inline_funcs):
    out = {}
    for f, entry in inline_funcs.items():
        out[entry['addr']] = {'name': f, 'type': entry['type']}    
    return out

def is_libc(fname):
    return fname in libc_funcs

def is_gp(fname):
    return fname.startswith("TEE_") and not fname.startswith("TEE_SE")

def get_inline(inline, addr):
    if addr.getOffset() in inline:    
        return inline[addr.getOffset()]
    return None

def isname(fname):
    try:
        a = int(fname.split("FUN_")[-1],16)
        return False
    except:
        return True

def is_api_call(target, tee, inline_funcs):
    program = getCurrentProgram()
    fm = program.getFunctionManager()
    f = fm.getFunctionAt(target)
    print(target)
    if f is None:
        return True
    fname = f.getName()
    if isname(fname) and tee == "beanpod":
        return True
    if isname(fname) and tee == "teegris":
        return True
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
    
def get_api_type(target, tee, inline_funcs):
    program = getCurrentProgram()
    fm = program.getFunctionManager()
    f = fm.getFunctionAt(target)
    if f is None: 
        # one cause t6 entry is disassembled as arm but should be thumb
        return "tee"
    fname = f.getName()
    if is_gp(fname):
        return "gp_api"
    if is_libc(fname):
        return "libc"
    if fname.startswith("qsee_"):
        return "tee"
    if f.isExternal():
        return "tee"        
    inline_entry = get_inline(inline_funcs, target)    
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
        ghidra_func = fm.getFunctionAt(addressFactory.getAddress(func))
    if not ghidra_func:
        clearListing(addressFactory.getAddress(func))
        disassemble(addressFactory.getAddress(func))
        ghidra_func = createFunction(addressFactory.getAddress(func), None)
        if not ghidra_func:
            print("?????")
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
                        print(instr.getAddress())
                        is_api = is_api_call(target, tee, inline_funcs)
                        if is_api:
                            api_type = get_api_type(target, tee, inline_funcs)
                        else:
                            api_type = None
                        f = getFunctionAt(target)
                        if f:
                            f_name = f.getName()
                            if tee == "mitee" and f_name.startswith("xz_"):
                                # ipc is essentially a system call
                                svcs.append(str(instr.getAddress()))    
                                continue
                            if f_name.startswith("FUN_"):
                                f_name = str(target)
                            calls.append({"func": f_name, "api": is_api, "api_type": api_type})
                        else:
                            calls.append({"func": str(target), "api": is_api, "api_type": api_type})
                        if not is_api and str(target) not in func_cfgs and str(target) not in funcs_todo:
                            funcs_todo.append(str(target))
                            
            # Detect svc instruction (ARM/Thumb)
            if instr.getMnemonicString().lower() == "svc":
                svcs.append(str(instr.getAddress()))
            if instr.getMnemonicString().lower() == "swi":
                svcs.append(str(instr.getAddress()))

        bb_map[str(start)] = {
            "name": bb_name,
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
        "function": str(func),
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
    image_base = program.getImageBase()
    if image_base == addressFactory.getAddress("0x100000"):
        program.setImageBase(addressFactory.getAddress("0x0"), True)

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
        inline_funcs = convert(ta_info["inline"])
    else:
        inline_funcs = {}
    for ta_f in ta_fw:
        if ta_info[ta_f+'_start'] == -1: continue
        func_todo.append((hex(ta_info[ta_f+'_start'])))
    while(len(func_todo) != 0):
        func_todo_tmp = []
        for f in func_todo:
            cfg, todo = gen_cfg(f, func_cfgs, tee, inline_funcs)
            if cfg is None:
                continue
            print(str(f), todo)
            func_cfgs[str(f)] = cfg
            for f_todo in todo:
                if f_todo not in func_todo and f_todo not in func_cfgs:
                    func_todo_tmp.append(f_todo)
        func_todo = list(set(func_todo_tmp))

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
    print(out)
    open(out_path, "w").write(json.dumps(out, indent=4))
    os.system(f'chmod 666 {out_path}')
    return

if __name__ == "__main__":
    main()
