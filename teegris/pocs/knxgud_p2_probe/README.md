# knxgud_unlock — Knox Guard `kg_unlock` PROCA-soft-pass unlock bypass

Proof-of-concept for the **HIGH/CRITICAL** Knox Guard anti-theft / corporate-lock
bypass in Samsung's TEEGRIS `knxgud` TA.

- **TA / UUID:** `knxgud` — `00000000-0000-0000-0000-6b6e78677564` (ASCII tail `knxgud`)
- **Command:** `0x10A` (266) — `kg_unlock`
- **param_types:** `0x67` = `TEE_PARAM_TYPES(MEMREF_INOUT, MEMREF_OUTPUT, NONE, NONE)`
- **Both memref sizes:** exactly **17472** bytes (mandatory)
- **Severity:** HIGH/CRITICAL
- **Repro-status:** **CONFIRMED-IN-BINARY + dynamic BLOCKED (DEVICE-ONLY, PROCA)**

Sources: [`RE/samsung_teegris/knxgud.md`](../../../../code/ta-analysis/RE/samsung_teegris/knxgud.md)
(§"FINDING — HIGH/CRITICAL", lines 245-309; command table line 111; IPC surface
lines 59-143) and [`RE/emulation/knxgud.md`](../../../../code/ta-analysis/RE/emulation/knxgud.md)
(finding #1 lines 9-16; dynamic-block analysis lines 83-137).

## The bug

`TA_InvokeCommandEntryPoint` (`@0x1FE7C`) validates the param shape (`0x67`,
both memrefs == 17472) and then runs a **PROCA prelude** that is meant to bind
the caller to the genuine Samsung-signed `kg-service` daemon
(`/vendor/bin/hw/vendor.samsung.hardware.tlc.kg-service`) before any command
dispatch:

```
1. validate param_types == 0x67 and both memref sizes == 17472
2. TEES_GetClientCredentials                              -> pid
3. kg_proca_ctx_init / kg_proca_rules_add_name / _create_handler_from_pid
4. kg_proca_authenticate -> TEE_OpenTASession(PROCA UUID ...0050524f4341)
5. process_cmd(cmd_id, ...)        <- only runs if step 4 passed (or soft-passed)
```

**The fail-open.** `kg_proca_authenticate` returning **`1179648`** ("PROCA not
supported") or **`1114137`** ("custom kernel detected") is special-cased to
**log-and-continue** instead of bailing. Any other non-zero return correctly
goes to `-65535`. So on a **custom-kernel / PROCA-stripped device** — exactly
the adversary scenario Knox Guard is designed to defend against — the gate is
bypassed and `process_cmd` runs **without any caller binding**.

**The primitive.** `kg_unlock` (cmd `0x10A`, `@0x205B4`) is **parameterless**
and is a one-call unlock:

```
read_info_object -> read_wrap_data -> tz_unwrap_data_with_derived_key("kg_ta")
   -> check unwrapped len == 461
   -> unlock_counter += 1
   -> state = 2 (UNLOCKED)
   -> wrap + write back
```

No HOTP, no nonce, no signature, no server token. `kg_verify_complete_token`
(cmd `0x10B`) is the server-signed step unlock is *supposed* to follow, but
`kg_unlock` never checks that `0x10B` ran. **One call defeats the lock**, and
there is no device-side recovery once `state == 2`.

This is worse than VaultKeeper's same bug class: VLTKPR's soft-pass exposes many
handlers that each need extra REE state; knxgud's exposes a single direct unlock
with no per-call data dependency.

## Wire format

```
param_types == 0x67 = [MEMREF_INOUT, MEMREF_OUTPUT, NONE, NONE]
params[0]  (17472 B request):   [cmd_id:4 = 0x0000010A][zeros...]   (kg_unlock has no payload)
params[1]  (17472 B response):  [cmd_id|0x80000000:4 = 0x8000010A][result:4][...]
```

Both memref buffers MUST be exactly 17472 bytes — any other size short-circuits
with `-65530` / `-65535` before the PROCA prelude even runs.

## Build & run

```
make emulator     # builds ./poc with -DEMULATE (host gcc)
make phone        # cross-compiles via $ANDROID_NDK + adb push (real device)
```

The `emulator` target compiles `jni/poc.c` against the bundled `repro.h`
emulate-transport. To exercise it, start the knxgud TA in the emulator and run
`./poc` (see the emulator's `emu_start.sh` for the
`...6b6e78677564` UUID).

## Why it does not fire in the emulator (DEVICE-ONLY)

Per `emulation/knxgud.md` (lines 83-137): `TA_InvokeCommandEntryPoint` **halts
in its PROCA prelude** at the un-modeled `TEE_OpenTASession` (the TA→PROCA
TA-to-TA call, PROCA UUID `…0050524f4341`) **before** `process_cmd`. The
emulator models no PROCA peer, so that import routes to `gp_api.default_func`,
which **HALTS** rather than *returning* the `1179648` / `1114137` soft-code the
dispatcher's fall-through keys on. The TA therefore never evaluates
`if (rc == 1179648 || rc == 1114137)` and never reaches `kg_unlock`.

The bitter irony: the emulator (no PROCA peer) **is** the PROCA-absent condition
that triggers the bypass on a real device — but it can't demonstrate it, because
the not-implemented stub halts instead of returning the soft-code.

**Established in-emulator soft-pass.** The campaign already has a pattern for
exactly this: `vltkpr_authenticate_ca_softpass` — a `.json` **inline hook** that
stubs the TA's authenticate routine so the dispatch is reached (see
`vltkpr_verifycert/jni/poc.c` lines 19-26 and the hook in
`tas/00000000-0000-0000-0000-564c544b5052.json`). The knxgud analogue is an
inline hook on **`kg_proca_authenticate` (`@0x23B54`)** to return a soft-code
(`1179648` or `1114137`) so `TA_InvokeCommandEntryPoint` falls through to
`process_cmd`.

Even with that hook in place, the unlock path needs two more things the emulator
lacks, so a full dynamic unlock is the same triple-prerequisite block as
engmod #2 / FbCkmR / duldar:

1. a **real libcrypto** for the GCM unwrap (`tz_unwrap_data_with_derived_key`
   → `EVP_aes_256_gcm` / `EVP_DecryptUpdate`, un-modeled → HALT), and
2. a **provisioned RPMB info-object** — `read_info_object`'s `rot_check`
   (magic `0xEA030000`) fails on the fresh emulator's unprovisioned RPMB, plus
   `TEES_RPMBWrite` for the state persist.

Hence the verdict **CONFIRMED-IN-BINARY + dynamic BLOCKED**: the finding's code
(soft-pass waivers + `kg_unlock`) is verbatim present in the emulator's own
S9BYH2 build, the TA loads and boots (`EMU_READY`, `CreateEntryPoint for KG`),
but the bypass can only be exercised on a real custom-kernel device.

## Secondary finding (MED, not driven here): cert-purpose confusion

`kg_provision_cert` (cmd `0x117`) base64-decodes four PEM certs
(enroll/bl/hotp/policy) and chain-verifies **all four against the same**
hardcoded `Samsung Service Server CA - class 2` anchor with **no EKU /
purpose-OID check** (only a dev-cert pubmod denylist). A single Samsung-CA-signed
leaf valid for one role is therefore accepted in any slot — **cross-role cert
substitution** (`knxgud.md` §"NEW FINDING — MED", lines 435-456). It rides the
same dispatcher front-door (param_types `0x67`, both memrefs 17472, cmd `0x117`),
and is gated by the same soft-passable PROCA check, but exploitability requires
a Samsung-CA-signed cert (insider / CA-compromise), so it is left documented
rather than weaponized in this PoC.
