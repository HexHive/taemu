# Static analysis (Ghidra, headless)

Recovers, per TA, what the emulator and the coverage figures need from the
binary:

* the entry-point offsets in `<tee>/tas/<uuid>.json` — where
  `TA_InvokeCommandEntryPoint` and friends start and end. Without these the
  emulator cannot invoke a TA.
* the basic-block CFG in `<tee>/tas/bbs/bb_<uuid>.ta.json` — Figure 4
  normalises coverage by the blocks reachable from
  `TA_InvokeCommandEntryPoint`.

**Both ship with the artifact**, so no experiment runs Ghidra and it is not
installed in either image. This directory is here so the analysis can be
reproduced or extended to new TAs.

## Running it

```sh
cd ghidra
make build                 # builds the ghidrathon headless image
./analyze-bbs.sh           # CFGs for every TA of every TEE -> <tee>/tas/bbs/
./analyze-mitee.sh         # entry-point offsets, one script per TEE
./analyze-teegris.sh
./analyze-beanpod.sh
./analyze-optee.sh
```

    Dockerfile, compose.yaml  the headless Ghidra + Ghidrathon image
    docker/*-entrypoint.sh    what runs inside it per TEE
    src/ghidra_scripts/       the analysis scripts themselves:
                              coverage_bbs.py (the CFG export),
                              <tee>_funcs.py  (per-TEE entry-point recovery),
                              libc_funcs.py, helpers.py, utils.py (support)
