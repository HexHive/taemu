# skm_drk — Device Root Key exfiltration via missing ACL (skm / DEVROOT#SKM)

- **TA:** skm (Samsung Key Manager, banner `DEVROOT#SKM`)
- **UUID:** `00000000-0000-0000-0000-000000534b4d` (ASCII tail `SKM`)
- **cmd_id:** `48163` / `0xBC23` → `skm_readDrkFromHwvault` (`@0x1807C`)
- **param_types:** `0x7` = `TEEC_PARAM_TYPES(MEMREF_TEMP_INOUT, NONE, NONE, NONE)`
- **Severity:** HIGH (DRK exfiltration)
- **Repro-status:** DEVICE-ONLY

## Finding

SKM's inner dispatcher `skm_taCmdExecute` (`@0x19320`,
`src/skm/teeCmdExecuter.c`) is a 14-arm `if/else if` ladder over the
REE-supplied 32-bit `cmd_id`. One arm, **cmd `0xBC23`**, calls
`skm_readDrkFromHwvault` (`@0x1807C`), which performs a raw
`HwVaultHal_readCred(1, ...)` and returns the device's **Device Root Key**
straight back to the REE (RE/samsung_teegris/skm.md:99, :168).

Nothing authenticates the caller: `skm_invoke_acl_check` (`@0x1BA94`) is
compiled as a bare `return 0;` stub on this build, so *any* REE component that
can open a TEEGRIS session to SKM can reach *any* command, including the DRK
read (skm.md:164, :169). The RE flagged the open-ACL precondition
**NEEDS-EXTERNAL-VERIFICATION** (the examined image is a `fac` build; a
production/non-fac SKM is required to confirm the ACL stays a stub there).

## Wire format (skm.md:67–76)

One `MEMREF_INOUT` in `params[0]`, capacity bounded to `0x2000`:

```
[u32 cmd_id]
[u32 payload_len]   // <= 0x2000
[u8  payload[]]     // Samsung-TLV (sentinel 0xFE)
```

`param_types` low nibble **must** be `7`, else the dispatcher returns `-12002`
("Invalid param_types."). The raw DRK read needs no TLV input, so this PoC
sends `payload_len = 0` and a single INOUT buffer; the handler writes the DRK
material back into that same buffer.

## What the PoC does

1. `load_functions()` → `InitializeContext` → `OpenSession(TEEC_LOGIN_PUBLIC)`
   (no credentials — reachable because the ACL is a stub).
2. Allocates a `0x2000` INOUT buffer via `allocate_param_mem`, writes
   `[u32 0xBC23][u32 0]` at the head.
3. `InvokeCommand(0xBC23, paramTypes=0x7)`.
4. `DumpHex`es the response buffer (where the DRK would land).

## Repro status — DEVICE-ONLY

The *reachability* (missing-ACL `return 0` stub) is **CONFIRMED-IN-BINARY** and
is the entire reason a REE caller lands in this handler
(RE/emulation/skm.md:9–15). The actual DRK read, however, goes through the
**`/dev/hwvault` kernel driver**, which the emulator does **not** model — no
hwvault driver, no HWVAULT ROT, no provisioned device DRK
(emulation/skm.md:49, :83–90). So under the emulator the session opens and cmd
`0xBC23` dispatches (demonstrating the un-authenticated reachability), but
there is no key material to return — the buffer stays zero. **The exfiltration
completes only on real hardware with a provisioned DRK.**

## Secondary finding (LOW, static-only — documented, not triggered)

`skm_verifyKeyPairConsistency` (`@0x18C24`) draws a 32-byte challenge via
`TEE_GenerateRandom`; if that call returns `!= 32` bytes it falls back to the
hardcoded ASCII literal `1234567890qwertyuiop[]asdfghjkl`, signs it with the
DRK key, and verifies (skm.md:201–215). An attacker who can fault-inject an RNG
failure and observe the sign output learns a fixed-challenge DRK signature.
This lives on the RNG-**failure** branch, which the emulator's never-failing
`TEE_GenerateRandom` cannot reach (emulation/skm.md:92–103), so this PoC does
**not** exercise it — it is recorded here as static-only.

## Build / run

```
make emulator      # gcc -DEMULATE -> ./poc   (drives the emulator on :1337)
make phone         # ndk-build armeabi-v7a, adb push to /data/local/tmp
```

Start the emulator for SKM first, e.g.
`emu_start.sh 00000000-0000-0000-0000-000000534b4d skm_load` (SKM loads + boots
live, EMU_READY ~2s — emulation/skm.md:68–73), then `make emulator` and run
`./poc`.
