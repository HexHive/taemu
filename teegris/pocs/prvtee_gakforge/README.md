# prvtee_gakforge — GAK SecureObject forge via the zero creator-id-2 slot

Proof-of-concept for the headline finding on **PRVTEE** (Samsung Knox
`DEVROOT#PROV` DRK-provisioning trustlet).

- **TA / UUID:** PRVTEE — `00000000-0000-0000-0000-505256544545`
  (ASCII tail `PRVTEE`).
- **Finding:** creator-id-2 zero-slot → **GAK-SO** (GateKeeper / Generic-Auth-Key
  SecureObject) **forge**.
- **Severity:** MED — **NEEDS-RUNTIME-CONFIRMATION**.
- **Sources:** [`RE/samsung_teegris/prvtee.md`](../../../../code/ta-analysis/RE/samsung_teegris/prvtee.md),
  [`RE/emulation/prvtee.md`](../../../../code/ta-analysis/RE/emulation/prvtee.md).

## The bug (RE/samsung_teegris/prvtee.md, "SecureObject creator-id trust model", lines 311-343)

PRVTEE's SecureObject creator-id table (`prv_get_creator_id_entry` @0x23A18,
stride 544) has three entries:

| a1 | slot | binding |
|----|------|---------|
| 1 | `unk_63E8+544`  | **creator-id-1** = SKM — gates `prvtee_encryptCSR` (the CSR handoff). SAFE: bound to SKM's TID, kernel-enforced. |
| 2 | `unk_63E8+1088` | **creator-id-2** — `prvtee_unwrapGakBlob` wraps the decrypted GAK into an SO with this id. **All-zero on this build.** |

`prvtee_unwrapGakBlob` (cmd **42754 / 0xA702**, lines 101, 138-141) decrypts a
SWBC-protected GAK blob and then re-wraps it as a SecureObject via
`sub_247FC` (`prv_createSecureObject`) **with creator-id 2**
(`sub_23A18(2) + sub_23A74(2)`). The call at `0x18AF8` passes the
**zero TID** from slot 2 to `TEES_WrapSecureObject`. A zero/empty creator TID
produces an SO with **no inter-TA ACL** — "any TA can unwrap it" (line 334-335).
That is the forge: any peer that can reach the GAK consumer
(likely VaultKeeper / Knox Vault, line 140-141) could pre-wrap arbitrary bytes
as a *valid* GAK SecureObject.

The same zero slot is reachable through the **encryptCSR trampolines**
(lines 219, 225): cmds **43011 / 0xA803** (`W0=1`) and **43012 / 0xA804**
(`W0=2`) fall through to the shared body at `0x18BEC`, where `sub_23A18(W0)`
selects the creator-id binding and `(W0-1)>1 → "Not supported AppId"` limits
AppIds to `{1,2}`. **W0=2 (cmd 43012) selects the same zero creator-id-2 slot.**

### LOW (documented, benign) — `prvtee_unwrapGakBlob` 4-byte stack over-write

`sub_4BD98` (SWBC decrypt) does `memcpy(a3, v15, n)` with `n ≤ 0x4000`, where
the caller passes `a3 = v28[16380]` — 4 bytes short of the `0x4000` cap. A
worst-case decrypt writes **4 bytes past `v28`** into stack padding at
`[xbp-0xC, xbp-0x8)`. The canary `v29` at `[xbp-0x8]` is untouched and the
overrun lands in dead padding → **not exploitable** (RE lines 345-354). This
PoC's max-length (`0x4000`) tag-6 body is the input that would drive that
write, so the same wire path also reaches the LOW.

## Wire format (RE/samsung_teegris/prvtee.md lines 79-85)

```
params[0] = single MEMREF_INOUT;   (param_types & 0xF) == 7
buffer:
    [u32 cmd_id]
    [u32 payload_len]
    [u8  payload[]]      // Samsung-TLV: 0xFE sentinel, then <tag:u8><len:u16 LE><value>
```

For cmd 42754 the payload carries two TLV records (lines 117-118):

| tag | meaning | constraint |
|-----|---------|------------|
| 2 | AES IV | **exactly 16 bytes** (`Invalid IV length %d.` panic) |
| 6 | encrypted GAK blob | length `≤ 0x4000` |

The PoC builds exactly this: `0xFE`, `tag2`(16-byte IV), `tag6`(GAK blob,
up to `0x4000`), inside an `op.params[0]` `MEMREF_TEMP_INOUT` whose
`paramTypes == 0x7` (low nibble 7).

## What the PoC does (`jni/poc.c`)

1. `load_functions()` → `InitializeContext` → `OpenSession(TEEC_LOGIN_PUBLIC)`
   (PRVTEE's `TA_OpenSessionEntryPoint` has no caller check, line 73).
2. **cmd 42754** `unwrapGakBlob` with the tag2+tag6 TLV — the command that
   mints the GAK SO bound to the zero creator-id-2 slot. The tag-6 body is
   sized `0x4000` to also reach the LOW 4-byte over-write.
3. **cmd 43012** (`W0=2`) and **cmd 43011** (`W0=1`) encryptCSR trampolines —
   to show on the wire that the variant-B path selects the same zero
   creator-id-2 slot (43011 selects creator-id-1=SKM, for contrast).

## Build / run

```sh
cd prvtee_gakforge && make emulator        # gcc -DEMULATE -> ./poc
# on device:  make phone   (needs ANDROID_NDK; pushes to /data/local/tmp/)
```

Run against the emulator after `emu_start.sh …505256544545 prvtee_…`.

## Repro status — **DEVICE-ONLY / NEEDS-RUNTIME** (RE/emulation/prvtee.md)

The forge **cannot be demonstrated end-to-end on the emulator**, by three
independent blocks documented in `RE/emulation/prvtee.md`:

1. **The forge primitive is un-modeled.** `TEES_WrapSecureObject` — the call
   that mints the forged GAK SO — is UN-implemented and routes to
   `default_func` → HALT (lines 102-121). Even granting an open ACL, there is
   no modeled path to mint the SO.
2. **The zero-slot is a per-device provisioning property.** Whether
   creator-id-2 ships zero is a `.data.rel.ro` relocation / provisioning
   property of a specific image, not a behaviour the emulator decides
   (lines 74-85, 146). The MED is fundamentally about **production devices**.
3. **The corpus binary ≠ the RE binary (offsets do not transfer).** The
   emulator's `…505256544545.ta` (`S921BXXS9BYH20Y0`) is the **same size**
   (354,826 B) but **not byte-identical**: in the corpus image `0x63E8` is
   rodata (`.data.rel.ro` is seg2 @`0x4fec0`), and the inline-ASCII
   creator-id table at the RE offset does not exist (lines 36-85). So the
   per-offset addresses (`unk_63E8+1088`, `sub_4BD98`, `0x18AF8`) in the
   citations above are from the **RE build** and do **not** map onto this
   corpus build — they are cited for provenance, not as live addresses here.

The TA **loads + boots** (EMU_READY 2s) and all feature strings
(`TEES_WrapSecureObject`, `Invalid secure object creator`, `unwrapGakBlob`,
`swbc_prov.c`) are present in the corpus build, so this PoC drives the **real
GAK wire request**. On a production device whose creator-id-2 slot ships zero,
that request mints an **unbound, forgeable GAK SecureObject**; on the emulator
it reaches the handler and then dead-ends at the un-modeled
`TEES_WrapSecureObject` sink. The RE's **NEEDS-RUNTIME-CONFIRMATION** label
therefore stands.
