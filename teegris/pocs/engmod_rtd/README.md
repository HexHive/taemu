# engmod_rtd — cmd-24 (EM_CMD_TIME_CHECK) silent dev-CA-signed RTD accept

- **TA:** engmod (Samsung TEEGRIS EngineeringMode TA)
- **UUID:** `00000000-0000-0000-0000-656e676d6f64` (ASCII tail `engmod`)
- **Severity:** HIGH
- **Inner command:** `EM_CMD_TIME_CHECK` = **24** (`em_cmd_time_check @ 0x1ED2C`)
- **REPRO-STATUS:** **DEVICE-ONLY** (blocked in-emulator behind un-modeled libcrypto)

## The finding

Source: `RE/samsung_teegris/engmod.md` ("NEW FINDING — HIGH: `em_cmd_time_check`
(cmd 24) silently accepts dev-CA-signed RTD packets" and the
"MAC-verify + PROCA fail-open sweep" Finding 2); confirmation in
`RE/emulation/engmod.md` Finding #2.

`em_cmd_time_check` (cmd 24) verifies the inbound RTD (Remote-service Time Data)
packet with `em_crypto_verify_rsa_signature` and then treats the dev-cert
soft-success sentinel `-61403` **exactly like a production accept**:

```c
rc_verify_sig = em_crypto_verify_rsa_signature(/* RTD sig args */);
if ( rc_verify_sig != -61403 ) {        // -61403 = DEV-CA soft success
    ret = rc_verify_sig;
    if ( rc_verify_sig ) goto LABEL_9;  // real error -> bail
}
// rc == 0 (prod) OR rc == -61403 (dev) -> falls through and proceeds
```

The `-61403` is produced upstream in `em_crypto_verify_cert @ 0x11724`: the
PROD `X509_verify` fails (`"Check one more"`), the DEV-CA `X509_verify` then
succeeds (`"DEV Cert verify success"`), and `RSA_public_decrypt` yields the
soft-success sentinel. Whereas `em_token_verify_token @ 0x19FF4` at least sets
the `ctx+16 |= 0x80000000` dev-cert flag and logs the dev path on `-61403`,
**cmd 24 sets no flag and logs nothing** — a DEV-CA-signed RTD is
byte-for-byte indistinguishable from a production-signed one in every
downstream check.

**Impact:** a packet signed with the leaked Samsung EngineeringMode **DEV CA**
private key (modulus `c49fcb..` / `b28b83..`, embedded at `0x7EDE` / `0x7DB8`)
extends a token's `priority_time` validity window and records token state
`"DEL,R4"` with no audit trail. The outbound 64-byte RTD ACK is then encrypted
with the hardcoded fleet-wide key `"departmstggroup."` (see the sibling
`engmod_wbkey` POC), so the ACK can also be forged offline.

## Wire format (what the POC drives)

From `RE/samsung_teegris/engmod.md` "IPC surface" + "Inner command table":

- ONE GP TEE command. **The TA-cmd id passed to `TEEC_InvokeCommand` is
  IGNORED**; `em_cmd_handler @ 0x12D9C` reads the real command as
  `cmd_id = ctx->raw_cmd_id & 0xFFFF3FFF` out of the parsed request structure
  (top 2 bits are flag-mask reserved).
- `param_types == 0x77 == TEE_PARAM_TYPES(MEMREF_INOUT, MEMREF_INOUT, NONE, NONE)`.
- `params[0]` = `em_context_request`, **exactly 138365 bytes** (`0x21C7D`).
- `params[1]` = `em_context_response`, **exactly 133430 bytes** (`0x20936`).
- The entry shell `TA_InvokeCommandEntryPoint @ 0xE26C` rejects the command
  unless `param_types == 0x77` and both sizes match exactly, then
  `TEE_MemMove(ctx, params[0], 138365)` and `em_make_context_request` parse it
  before `em_cmd_handler` runs.

The POC builds a 138365-byte request whose inner cmd_id field = 24
(`24 & 0xFFFF3FFF == 24`), plus an RTD blob placeholder region.

### The signed RTD blob is external

The **actual** signed RTD blob (a DEV-CA-signed cert chain + RTD payload +
RSA-PKCS1 signature, `cert_len` in `[4097, 0x10000]`) is the artefact a real
attacker forges with the leaked DEV CA private key. This POC deliberately does
**not** carry live Samsung key material (authorized-research constraint). To
exercise the full path on hardware, drop the forged blob into `rtd_blob.bin`
next to the compiled `poc` binary and it is loaded over the placeholder at
request offset `0x100`.

## Why DEVICE-ONLY (blocked in-emulator)

Per `RE/emulation/engmod.md` Finding #2: the `-61403` branch is reachable only
*after* `em_crypto_verify_cert` runs `d2i_RSA_PUBKEY` → `EVP_PKEY_set1_RSA` →
`X509_verify` (PROD then DEV) → `RSA_public_decrypt`. The emulator models
**none** of those verbs — each falls through to `gp_api.default_func`
(`"<fn> called, not implemented!"`), which HALTs. So `em_cmd_time_check` dies
at the very first `d2i_RSA_PUBKEY`; the silent dev-CA accept can never be
driven in-emulator.

- **CONFIRMED-IN-BINARY:** the fallback-ladder strings (`Verifing cert is
  success`, `Check one more`, `DEV Cert verify success`, `Dev token is not
  allowed`) are byte-present in the bundled `.ta`.
- **Live accept:** reproducible only on real hardware with an un-stubbed
  libcrypto **and** a genuine DEV-CA-signed RTD blob.

Running this POC against the emulator engages the path and is expected to halt
at an un-implemented crypto import — demonstrating the request shape is
accepted by the entry shell and the verify chain is reached, which is exactly
the documented block boundary.

## Build & run

```sh
make emulator          # builds ./poc with -DEMULATE
# start the engmod TA in the emulator first, e.g.:
#   emu_start.sh ... 656e676d6f64 engmod_load   (see emulation/engmod.md)
./poc
```

`make emulator` adds `-Wno-incompatible-pointer-types` because GCC >= 14
promotes that warning to an error for an assignment inside the **shared**
`jni/repro.h` helper (identical for every POC in this tree); `poc.c` itself is
warning-clean. The reference POCs (`gatekeeper_throttle`, etc.) hit the same
`repro.h` error on this toolchain.

## Files

- `jni/poc.c` — the POC (all constants cited to the writeups inline).
- `jni/repro.h`, `jni/tee_client_api.h`, `jni/Android.mk`, `jni/Application.mk`,
  `Makefile` — copied verbatim from the campaign boilerplate
  (`gatekeeper_throttle`), except the Makefile's `-Wno-incompatible-pointer-types`
  note above.
