# esecom_verify — unverified session-key unwrap (ESECOMM_Verify_* `return 0` stub)

PoC for the Samsung TEEGRIS **esecom** TA (Samsung Pay eSE Communication
transport TA).

- **TA / UUID:** `esecom` — `00000000-0000-0000-0000-657365636f6d`
  (`RE/samsung_teegris/esecom.md` line 3).
- **Finding:** `ESECOMM_Verify_encapsulate_decapsulate` (`sub_BF74` @ `0xBF74`,
  renamed `ESECOMM_Verify_encapsulate_decapsulate_STUB`) is a **`return 0`
  stub** — body is zero instructions besides the RET. It is the routine that
  should verify the Secure Element's identity in the ECDH handshake before
  `esecom_cmd_UnwrapSessionKey` (@ `0xE744`) unwraps a session key. With the
  handshake entirely absent, the unwrap proceeds to AES-128-GCM
  encrypt/decrypt with **no** SE-peer verification.
  (`RE/samsung_teegris/esecom.md` follow-up #2, lines 288-304;
  `RE/emulation/esecom.md` lines 9-20.)
- **Severity:** HIGH (NEEDS-EXTERNAL-VERIFICATION)
  (`esecom.md` line 291; `emulation/esecom.md` line 96).

## Wire format

`TA_InvokeCommandEntryPoint` (@ `0x84B8`) requires
`param_types == 0x67 == TEE_PARAM_TYPES(MEMREF_INPUT, MEMREF_INPUT, NONE,
NONE)` and both MEMREF buffers must be `tciMessage_t` blobs sized in
`[0x1018, 0x2030]`; any other shape returns `-65530` (`TEE_ERROR_BAD_FORMAT`)
(`esecom.md` lines 50-54). `params[0]` is the request, `params[1]` the
response. The **leading request word** is `cmd_id | 0x80000000` and is copied
back in the response (`esecom.md` line 62).

| field | value | source |
|---|---|---|
| cmd_id | `0x20030` (131120) `CMD_TZ_ESECOMM_UnwrapSessionKey` | esecom.md line 80 |
| param_types | `0x67` (MEMREF_INPUT, MEMREF_INPUT, NONE, NONE) | esecom.md line 50 |
| params[0] +0x00 | leading word `0x80020030` (`cmd_id|0x80000000`) | esecom.md line 62 |
| params[0] +0x04 | 48-byte wrapped session-key SO (content irrelevant) | esecom.md lines 279-281, 251 |
| buffer sizes | `0x1018` each (min of the `[0x1018,0x2030]` range) | esecom.md line 53 |

The 48-byte body length is the `unwrapSkeySo_v2` (@ `0xFC08`) output gate
(`v9 == 48`) and the matching `WrapSessionKey` "48-byte size sentinel"
(`esecom.md` lines 279-281, 251). The blob **content** is irrelevant: the
verification the SE handshake should impose is exactly the `return 0` stub,
so any blob is accepted unauthenticated.

## Repro status — DEVICE-ONLY / BLOCKED

The stub itself is **CONFIRMED-IN-BINARY**: a function whose body is
`return 0` is a static property — reading it *is* the confirmation
(`emulation/esecom.md` lines 82-90, 96). The **consequence** (a
zero-verification unwrap) cannot be driven in the emulator because cmd
`0x20030` sits behind two un-modeled mechanisms, before the missing
verification even matters (`emulation/esecom.md` lines 61-96):

1. the **eng-build ICCC gate** `esecom_is_eng_build` (@ `0x9D84`) — requires
   `(IMAGE_STATUS_BL & 6)==4 && (IMAGE_STATUS_BOOT & 6)==4`, read via the
   **un-modeled ICCC peer** (`esecom.md` lines 80, 89-92);
2. the **`/dev/sec_ese` SPI eSE driver-client** reached via
   `secEseSelect → spiOpen` — **un-modeled kernel driver** (`esecom.md`
   lines 306-321).

On retail builds the path is silently unreachable; making it reachable
requires spoofing the eng-build ICCC bits via the **out-of-corpus** QSEE
`tz_iccc` SVB-clear of type `0xFF200001` (`esecom.md` line 220;
`emulation/esecom.md` line 80), itself NOT REPRODUCIBLE here.

So, run against the emulator, this PoC opens the session and issues the
invoke, but it is **EXPECTED to be rejected** at the dev-status / eng-build
gate (warranty/SVB ICCC reads → `9`, `esecom.md` lines 99-107) long before
the stub runs. On an eng-fused device with the eSE driver present, the same
request reaches the stubbed verify and the unwrap proceeds unauthenticated.
The static finding holds against the S921B binary regardless
(`emulation/esecom.md` lines 100-110).

## Build / run

```
make emulator       # gcc -g3 -O0 -DEMULATE jni/poc.c -o ./poc
```

then point it at a running esecom emulator instance
(`emu_start.sh …657365636f6d esecom_load`; `emulation/esecom.md` lines 54-60).
Host-side, `make phone` cross-compiles with the NDK for an on-device run
(`ANDROID_NDK` must be set).
