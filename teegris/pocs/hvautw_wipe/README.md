# hvautw_wipe — HvAUtW (`hwvault`) unauthenticated factory-reset / wipe

Proof-of-concept client for the Samsung TEEGRIS **`hwvault`** driver TA
("HvAUtW"). Covers two findings from
[`RE/samsung_teegris/hvautw.md`](../../../../code/ta-analysis/RE/samsung_teegris/hvautw.md)
and [`RE/emulation/hvautw.md`](../../../../code/ta-analysis/RE/emulation/hvautw.md):

| | finding |
|---|---|
| **(1) headline — runnable** | cmd **10020** `HV_TZ_CMD_FACTORY_RESET`: a REE caller opens a session and wipes the entire trusted store (KDM + weaver + all SecNVM slots) with **no auth gate**. |
| **(2) secondary — documented only** | `swd_hv_get_derived_key` 32-bit integer overflow. Reachable only via the **TA-to-TA driver ioctl** path, not from a REE process — documented below, no runnable client. |

- **TA:** `hwvault` GP TEE **driver** TA (`TEES_InitDriver("hwvault")`).
- **UUID:** `00000000-0000-0000-0000-487641557457` (ASCII tail `HvAUtW`).
- **GP entry param_types:** `0x65` =
  `TEE_PARAM_TYPES(MEMREF_INPUT, MEMREF_INOUT, NONE, NONE)`
  (`hvautw.md` lines 78-79, 916-920). Both memrefs are validated with
  `TEES_IsREESharedMemory` and the input is copied to the heap before parse
  (no double-fetch) — this is the **only** in-TA precondition, a shape check,
  not an authorization check.
- **TLV envelope** (shared with FbCkmR, both via `sub_F0F4`):
  `[u32 cmd_id][u32 payload_len L][TLV items...]`, `total = L + 8`. cmd_id is
  the first 4-byte word (`hvautw.md` lines 79-83, 112; `fbckmr.md` lines
  45-48, 105-110). TLV item = `{u32 tag; u32 len; u8 value[len]}`; tag high
  byte `0x01`=integer, `0x02`=bytes.

---

## Finding (1) — cmd 10020 `HV_TZ_CMD_FACTORY_RESET`, no auth gate (HIGH)

**What it is.** `hv_factory_reset` @ `0x130B4` (cmd 10020,
`re_teegris_hvautw.py:101,166`; `hvautw.md` line 208) wipes **all** hwvault
state — KDM (key-derivation material), the weaver slot table, and every
per-app SecNVM slot.

**Why it is reachable with no credential.** The inner dispatcher
`tz_process_command` @ `0xFD7C` applies **no per-command login / identity
gate**; every `HV_TZ_CMD_*` arm is reachable from the REE invoke path once a
session is open (`hvautw.md` finding #2, lines 313-330). `hv_factory_reset`
itself has no authsecret check, no bootloader signature, and no
caller-identity verification inside the TA (`hvautw.md` open-follow-up #4
RESOLVED, lines 940-942). The attack-surface table (line 250) flags it
directly: *"Should be gated to the bootloader factory-reset path; if a
normal-world process can hit it, this is total trust-store annihilation."*
**Status (auth gap): CONFIRMED-IN-BINARY.** Whether an *external*
kernel-`samsung_drv`/SMC caller-UUID gate exists is
NEEDS-EXTERNAL-VERIFICATION (out of this PoC's scope).

**The request the TA expects.** `hv_factory_reset` takes **no body
argument** — unlike the cred/persistent-cred handlers (cmd 10014-10019,
which read a `slot_id`) or SET_KDM / weaver (which read blobs), the
factory-reset arm wipes everything wholesale. So the minimal valid request
is just the 8-byte envelope header with zero trailing TLV items:

```
offset 0:  u32  cmd_id      = 10020   (HV_TZ_CMD_FACTORY_RESET)
offset 4:  u32  payload_len = 0       (no TLV items follow)
total = 8 bytes  (satisfies sub_F0F4's `payload_len + 8 == total` invariant,
                  hvautw.md lines 904-905)
```

**What `poc.c` does.** `load_functions()` → `InitializeContext` →
`OpenSession(TEEC_LOGIN_PUBLIC)` (no creds) → build the
`[10020][0]` envelope in `params[0]` → `InvokeCommand(cmd=10020)` with
`op.paramTypes` wired to the on-wire value `0x65` and
`params[1]` as the INOUT response memref.

### param_types nibble note (grounded)

`hvautw.md` names `0x65` as `TEE_PARAM_TYPES(MEMREF_INPUT, MEMREF_INOUT, ...)`.
The TEE-side GP enum is `{MEMREF_INPUT=4, MEMREF_OUTPUT=5, MEMREF_INOUT=6}`
(`emulator/emulate/gp/utils/param.py:5-7`), whereas the client TEEC enum is
`{TEMP_INPUT=5, TEMP_OUTPUT=6, TEMP_INOUT=7}` (`tee_client_api.h:113-115`).
The on-wire byte that satisfies the TA's `== 0x65` gate is produced by
`TEEC_PARAM_TYPES(TEMP_INPUT, TEMP_OUTPUT)` = `5 | (6<<4)` = **0x65** — the
exact convention used by every other working `0x65` PoC in this corpus
(`keymst_hmacfinish/poc.c:174`, `semese_dercert`, `fbckmr_import/poc.c:103`).
Using `TEMP_INOUT=7` for `params[1]` would yield `0x75` and the gate would
reject it, so `poc.c` encodes the `MEMREF_INPUT, MEMREF_INOUT` *intent* with
the client constants that wire up to `0x65`.

### Repro status — PARTIAL (missing-gate reachable in-emulator; wipe effect device-only)

Per `RE/emulation/hvautw.md` (finding #2, lines 84-119; build-delta note
lines 9-31):

- **missing-auth-gate** — **CONFIRMED-IN-BINARY** (static). The control-flow
  fact "no per-command auth before `hv_factory_reset`" is established from the
  dispatcher disassembly; it does not depend on dynamic execution.
- **cmd 10020 presence** — cmd 10020 **IS present** in the bundled `S9BYH2`
  emulator build (`emulation/hvautw.md` line 90:
  `grep -aoc HV_TZ_CMD_FACTORY_RESET -> 1`). This is unlike the cmd-10036
  heap-overflow→RCE chain, whose entire handler is **code-absent** in `S9BYH2`
  (the SECNVM-manifest feature post-dates this build — `emulation/hvautw.md`
  lines 9-31, 40-63). So *this* PoC exercises a command that actually exists
  in the shipped binary.
- **loadability caveat** — HvAUtW is a *driver* TA; its `.json` has an empty
  `TA_DestroyEntryPoint_end`, which `ta_mgr.py` hard-rejects on load
  (`emulation/hvautw.md` lines 93-101). As shipped the driver TA may not load
  without a hand-patched `.json`; the session-open + dispatch path the missing
  gate lives on is what this PoC drives once it does.
- **wipe EFFECT** — **DEVICE-ONLY**. `hv_factory_reset` calls SecNVM/SPU wipe
  routines (`cm_ssp_snvm`) the emulator does not model
  (`emulation/hvautw.md` lines 112-114). The destructive KDM/weaver/SecNVM
  annihilation is observable only on real Exynos S24/A55 hardware.

So this PoC demonstrates the **reachability of the wipe with no credential**
(the finding), not the destructive side effect (device-only).

---

## Finding (2) — `swd_hv_get_derived_key` 32-bit integer overflow (MED) — DOCUMENTED, TA-to-TA / device-only

**No runnable TEEC client is provided for this finding, by design:** it is on
the **inter-TA driver ioctl surface (surface B)**, not the REE→TA invoke
surface a standalone normal-world process can reach.

**The bug** (`hvautw.md` finding #5, lines 819-843). `swd_hv_get_derived_key`
@ `0x15E78` builds a concatenation buffer sized by a 32-bit sum but only
rejects the *exact* value `-1`:

```
total = cred_len(*(v31[0]+4)) + a2(salt_len)        ; v16
0x15FB4  CMN W8,#1 ; B.EQ ...   ; reject ONLY total == 0xFFFFFFFF
total = total + a4(data_len)                         ; v17
0x15FC0  CMN W0,#1 ; B.EQ ...   ; reject ONLY total == 0xFFFFFFFF
0x15FC8  BL  .OPENSSL_malloc(total)
   ... memcpy(v18, cred, cred_len);
       memcpy(+cred_len, a1, a2);
       memcpy(+cred_len+a2, a3, a4)
```

A genuine `2^32` wraparound (e.g. `cred_len + a2 + a4 == 0x100000000` →
`total == 0`) passes both `!= -1` guards, so `malloc` is undersized while the
three `memcpy`s write the full unwrapped byte count → heap overflow.
**Status: overflow guard CONFIRMED-WRONG-IN-BINARY.**

**Why a standalone REE process cannot reach it.** The vulnerable function is
invoked only through `tz_drv_handler` @ `0xA780` sub-op `*v6 == 2` — the GP
TEE **driver ioctl** path (`TEES_DriverIoctl`), used by *sibling TAs*
(`hvautw.md` IPC surface B, lines 85-94; finding #5 line 836). That path:

1. Requires a **`TEES_OpenDriver("hwvault")` handle**, which the GP TEE only
   grants to another TA in-TEE — there is no REE client API that opens a
   driver handle and issues a driver ioctl. The REE-facing `TEEC_*` client
   protocol drives only `TA_InvokeCommandEntryPoint` (surface A,
   `param_types==0x65` TLV invoke); it has no opcode for the driver-ioctl
   surface (`emulation/hvautw.md` finding #5, lines 133-137).
2. Is **ACL-gated** by a TA-name + slot_id allowlist
   (`SEC_FR / FINGER / KEYMST / SKM / HwBStE / SEMeSE`), rejection log
   `Not permitted TA(%s) or slot_id(%u)` (`hvautw.md` lines 89-94, 836-838).
   A normal-world process has no TZ-attested TA name to present.

**Practical impact is DoS-class even from a permitted sibling TA.** `a2`/`a4`
source the fixed ~3080-byte inter-TA buffer, so reaching a multi-GB length
faults on the `memcpy` *read* before the wrap can be weaponized
(`hvautw.md` lines 838-842). **RCE exploitability:
NEEDS-EXTERNAL-VERIFICATION** (depends on whether any caller can supply a
large backing buffer).

**Emulator status: NOT REPRODUCIBLE — wrong surface.** The emulator's
interactive `:1337` TEEC protocol only drives the REE→TA invoke surface; it
has no mechanism to open a driver handle and issue an ioctl as another TA,
and HvAUtW is un-loadable anyway (`emulation/hvautw.md` finding #5, lines
121-140). The sibling-of-this-class latent twin `unwrap_blob` @ `0x1408C`
(finding #6) shares the same defective guard but is likewise
**NOT-REE-REACHABLE** (it only unwraps the TA's own self-wrapped cache
blobs) and is omitted here.

> NOTE: the separate cmd-10036 heap-overflow → unsafe-unlink → **RCE** chain
> (`hvautw.md` findings #1/#3/#4/#4a-#4g) is already fully developed as
> standalone Python PoCs at
> `ta-analysis/scripts/exploit/hvautw_{unlink,groom,codeexec}_poc.py` and is
> **not** re-implemented here. cmd 10036 is code-absent from the bundled
> `S9BYH2` emulator build (`emulation/hvautw.md` lines 9-31, 40-63), which is
> why those PoCs run the carved real `libtzsl.so` under Unicorn instead of
> this emulator.

---

## Build & run

```sh
cd hvautw_wipe
make emulator        # -> ./poc  (host x86-64, -DEMULATE)
# then, with the emulator listening on 127.0.0.1:1337 and HvAUtW loadable:
./poc
```

`make docker` builds and runs inside the `emu` container; `make phone` builds
an `armeabi-v7a` binary via the Android NDK and `adb push`es it (on-device
path — uses the real `libTEECommon.so`).

**Build note (gcc-16 on this host).** The verbatim `jni/repro.h` (copied
byte-identical from `gatekeeper_throttle/jni`) assigns a
`TEEC_TempMemoryReference*` into the `TEEC_SharedMemory* shm_p[]` table at
`repro.h:463`. gcc-16 promotes `-Wincompatible-pointer-types` to a hard error
by default, so the Makefile's `emulator` and `docker` recipes (and only
those) add `-Wno-incompatible-pointer-types`. The 4 headers/mk
(`repro.h`, `tee_client_api.h`, `Android.mk`, `Application.mk`) are kept
byte-verbatim. The residual `-Wdiscarded-qualifiers` warnings also originate
in the verbatim header and are harmless.
