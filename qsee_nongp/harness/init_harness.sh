#!/bin/bash

set -e

[ -z "$1" ] && echo "usage: $0 <path to ta>" && exit 1

ta_path=$1
[ ! -f "$ta_path" ] && echo "TA not found" && exit 1
ta_name=$(basename "$ta_path")


#Adjacent
yml_path=${ta_path%.*}.yml
echo "Using TA YML: $yml_path"
[ ! -f "$yml_path" ] && echo "TA YML not found" && exit 1

echo "Using TA: $ta_name"
script_dir=$(dirname "$0")
harness_dir=$(realpath ${script_dir}/harness_${ta_name%.*})
echo "Harness directory: $harness_dir"


mkdir -p ${harness_dir}/{in,out}
ln -sfr -t "$harness_dir" "$ta_path" "$yml_path"


cat <<HARNESS_EXAMPLE >${harness_dir}/harness.py
from typing import TYPE_CHECKING
import pwn
from qiling import Qiling
from pathlib import Path


if TYPE_CHECKING:
    from emulator.emulate.non_gp.qsee.params import QseeCommandParams, setup_qsee_fuzz
else:
    from emulate.non_gp.qsee.params import QseeCommandParams, setup_qsee_fuzz

filename = Path(__file__).stem.replace("_fuzz", "")


def place_input_callback(ql: Qiling, input: bytes, iters: int):
    del iters  # We are not using pers iters
    ql.log.info("%s custom harness!!!! Placing input: %s", filename.upper(), input[:10])

    # Example setup
    REQ_LEN = 0x1000
    RSP_LEN = 0x1000
    if len(input) < 8:
        return False

    cmds = [1,2,0xc001]
    cmd = cmds[input[0] % len(cmds)]

    data = pwn.flat({0: pwn.p32(cmd), 4: input[1:]})

    data = data[:REQ_LEN]
    data = data + (REQ_LEN - len(data)) * b"\x00"

    cmd_params = QseeCommandParams(data, req_len=REQ_LEN, rsp_len=RSP_LEN)

    setup_qsee_fuzz(ql, cmd_params, input)
    return True
HARNESS_EXAMPLE