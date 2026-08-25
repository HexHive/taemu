# Differential testing: emulator vs. device

The emulator's Python GP lib approximates the real TEE (heap layout,
uninitialized memory, allocator behavior, crypto edge cases). This harness runs
the **same input** through both and flags divergence — which is either an
emulator-fidelity gap (fix it; the emulator improves) or genuinely interesting
TA behavior. It also turns "is my emulator faithful?" into a measured quantity.

It reuses the project's existing dual-build: one POC source compiles against the
emulator (`-DEMULATE`, over the `:1337` socket) and the phone (NDK + real
libTEEC). So one vector-driven POC produces both records.

## Files
- `vector.py` — the oracle: vector/record schema, `compare()`, and `genheader`.
- `difftest_poc.c` — generic vector-driven POC; emits a JSON record to stdout.
- `vector.example.json` — a sample vector.

## Workflow
1. Write a vector (`vector.example.json` is a template): the command id, the four
   `param_types`, and each param's bytes/values.
2. Bake it into a C header:
   ```sh
   python3 vector.py genheader vector.example.json > vector.h
   ```
3. Build + run both ways (copy the InitializeContext/OpenSession boilerplate for
   your target TEE from its existing POCs — login method etc. are TEE-specific):
   ```sh
   # emulator (TA already running via ../../emulator/run.sh)
   gcc -DEMULATE difftest_poc.c -I<project includes> -o poc && ./poc > emu.json
   # device
   ANDROID_NDK=... ndk-build && adb push poc /data/local/tmp && \
     adb shell /data/local/tmp/poc > dev.json
   ```
4. Compare:
   ```sh
   python3 vector.py compare emu.json dev.json
   ```
   `MATCH` or a list of divergences (return code, per-param size/byte offsets).

## Status
`vector.py` (schema + `compare()` + `genheader`) is unit-tested and dependency-
free. `difftest_poc.c` is a template: the operation build + record emit are
complete; the per-TEE context/session boilerplate is yours to fill in (one
copy-paste from an existing POC). Running the device side needs your phone.

## Recorded-trace mode (no device handy)
You can also capture a device record once and keep it as a golden file, then
re-run only the emulator side after emulator changes and `compare` against the
golden — catching fidelity regressions without the phone each time.
