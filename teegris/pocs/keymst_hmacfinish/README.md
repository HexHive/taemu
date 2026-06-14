# keymst_hmacfinish — KEYMST HMAC empty/truncated-MAC verify bypass (HIGH)

Proof-of-concept for the `km_hmac_finish` empty/truncated-MAC verify bypass in
Samsung's TEEGRIS **KeyMint** TA (`skeymint`).

- **TA:** KEYMST (`skeymint`)
- **UUID:** `00000000-0000-0000-0000-4b45594d5354` (ASCII tail `KEYMST`)
- **Severity:** HIGH
- **Login:** `TEEC_LOGIN_PUBLIC` (the public KeyMint HAL surface, `login_method == 4`)
- **param_types:** `0x65` = `TEE_PARAM_TYPES(MEMREF_INPUT, MEMREF_OUTPUT, NONE, NONE)`
  - `params[0]` = KM_INDATA request blob, `params[1]` = KM_OUTDATA response
- **Primary command:** keymint **cmd 10** `swd_finish`
- **Secondary command:** keymint **cmd 1** `swd_add_rng_entropy` (LOW/MED)

## The bug (primary)

Source: `RE/samsung_teegris/keymst.md` §"Vulnerability findings" **#3** (lines 568-611).

`km_hmac_finish` (`0x40E04`, HMAC-finish vtable slot `0x9D3B8[0]`), reached via
**cmd 10 `swd_finish` (`0x3E850`) → `0x3E4CC` finish dispatch**, computes the full
HMAC over the message, then compares it against the **REE-supplied** MAC using a
`min(user_len, computed_len)` length:

```
0x40f34  LDRSW X10,[X9]          ; user_sig_len   (X9 = signature struct)
0x40f38  LDR   X0,[X9,#8]        ; user_sig_data
0x40f3c  CMP   X10, X8           ; user_len vs computed_len (X8)
0x40f40  CSEL  X2, X10, X8, CC   ; X2 = min(user_len, computed_len)
0x40f44  BL    .CRYPTO_memcmp
0x40f48  CBZ   W0, loc_41108     ; equal -> return 0 (VERIFY SUCCESS)
```

With **`user_sig_len == 0`** the `CSEL` selects `0`, `CRYPTO_memcmp(data, computed, 0)`
returns `0`, and control falls to `loc_41108` (`return 0` = success): **HMAC
verification of any message succeeds with an empty MAC and zero knowledge of the
key.** A truncated prefix of length `k < full` verifies likewise (supply only the
first `k` correct bytes). The signature struct is the *only* thing null-checked
(`0x40e5c CBZ X8`) — a present struct whose `len == 0` is **not** rejected. The
`MAC_LENGTH` tag (`0x300003EB`) is presence-checked only and consumed solely in the
SIGN branch; `MIN_MAC_LENGTH` is never consulted in verify, so the per-key minimum
is bypassed too.

The MAC `{len@+0, data@+8}` struct is wholly REE-controlled: `set_args_from_in`
(`0x3E248`) does `a2[3] = a1[8]`, copying the REE input's signature pointer into
op-arg `+0x18` — exactly the slot `km_hmac_finish` reads (keymst.md:601-606).
Status: **CONFIRMED-IN-BINARY**.

### Trigger

`begin(VERIFY)` an HMAC key (cmd 8) → `update(message)` (cmd 9) → **`finish()` with a
signature struct whose `len == 0`** (cmd 10). The empty/zero-length MAC short-circuits
the compare. This PoC issues the finishing verify with `SIG_LEN == 0`.

## The bug (secondary)

Source: keymst.md §"Vulnerability findings" **#2** (lines 545-560). `swd_add_rng_entropy`
(`0x38A3C`, cmd 1) caps entropy at 2048 with a **signed** compare
(`0x38A64 CMP W1,#0x800 / 0x38A68 B.LE`), so a length with the top bit set (e.g.
`0x80000001`) passes the cap and is handed to `RAND_seed` as `num`. Length lives at
struct `+0` (`LDR W1,[X8]`), buffer ptr at `+8` (`LDR X0,[X8,#8]`). The cap bypass is
CONFIRMED-IN-BINARY; the OOB impact is NEEDS-EXTERNAL-VERIFICATION (`RAND_seed` is an
out-of-ELF import). Same `0x65` wire — exercised here with `cmd_id == 1`.

## Wire format / what is and isn't pinned

The documented constants are exact: UUID, `param_types == 0x65`, the
`MEMREF_INPUT`/`MEMREF_OUTPUT` param layout, the keymint cmd ids (10, 1), and the
**trigger value `SIG_LEN == 0`**. The keymint `cmd_id` and the in-blob byte offset of
the signature struct travel inside the `d2i_KM_INDATA` (`sub_2F3F4`) ASN.1 template,
whose exact serialization the writeup does **not** byte-enumerate — so in `poc.c`
those positions are clearly-flagged `KM_INDATA_*_TODO` placeholders to be filled from
a device HAL capture, rather than invented offsets. Nothing load-bearing is guessed.

## REPRO-STATUS: DEVICE-ONLY

Per `RE/emulation/keymst.md`, the bypass is **BLOCKED in the emulator** by three
independent limits, so this PoC is the on-device trigger:

0. **Un-loadable as shipped** — KEYMST's `.json` has an empty
   `TA_CloseSessionEntryPoint_end`, so `ta_mgr.py` rejects the TA
   (emulation/keymst.md:37-62).
1. **Configure-gate** — cmd 10 is in mask `0x8000FFF75FFE`; `byte_A2858` is latched
   only by cmd 15 `swd_configure`, which does an outbound `TEE_OpenTASession` to the
   **STST (iccc)** sibling TA the emulator does not model (emulation/keymst.md:72-92).
   The in-emulator way past an STST trusted-boot round-trip is the **duldar STST
   soft-pass** — the `duldar` branch in `custom/session_payload.py:get_good_response_payload`
   (see `pocs/duldar_setuppw/jni/poc.c`, which relies on it for its own
   `verify_trusted_boot`). KEYMST additionally needs (2).
2. **No device key material** — reaching the verify-finish needs a live HMAC
   operation whose keyblob was unwrapped under the per-device **KAK**
   (`TEES_DeriveKeyKDF`, label `"KM QSEE HW Crypto Derived key"`) plus the HAT HMAC
   root from `ioctl(/dev/gatekeeper_driver)` — neither exists in the emulator
   (emulation/keymst.md:94-116). The bug itself does **not** need a *correct* key
   (`memcmp` len 0 short-circuits); the obstacle is purely *reaching* the
   verify-finish.

The static finding stands against the real S921B (`SFDZE1`) / A556B binaries.

## Build & run

```sh
make emulator     # standalone gcc -DEMULATE client over the emulator socket
./poc             # connects to 127.0.0.1:1337 (the emulator)
```

> Build note: this POC's `Makefile` adds `-Wno-incompatible-pointer-types` to the
> `emulator`/`docker` recipes — the **only** divergence from the verbatim
> `gatekeeper_throttle` Makefile. The shared shim `jni/repro.h` (copied byte-identical)
> has a `TEEC_TempMemoryReference*`→`TEEC_SharedMemory*` assignment at `repro.h:463`
> that gcc ≥14 (this host: gcc 16.1.1) rejects by default; every sibling POC's
> `make emulator` fails identically on it. `poc.c` itself compiles clean.

On device: `make phone` (requires `ANDROID_NDK`; pushes `poc` to
`/data/local/tmp/`).
