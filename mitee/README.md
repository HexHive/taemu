# MiTEE

TA corpus, harnesses and PoCs for Xiaomi's MiTEE. See
[`../README.md`](../README.md) §1 for what each subdirectory holds and §5 for
how the experiments use them.

## Provenance

| | |
|---|---|
| firmware | `lapis_images_OS2.0.202.0.VPPCNXM` |
| handset | `lapis` — Redmi Note 15 Pro |

Table I: 12 GlobalPlatform TAs, 10 of which operate directly on shared memory.

## Contents

    tas/                            12 TAs, with .json entry-point offsets and bbs/ CFGs
    harness/377e_double_fetch_stackov  377ee4e8…  SoterApp (Table II, stack overflow)
    harness/377e_fuzz                  377ee4e8…  SoterApp, plain exploration harness
    harness/3d08_fuzz                  3d08821c…  VSIMApp (Table II, oob write + double free)
    harness/59a4_fuzz                  59a4867c…
    harness/655a_fuzz                  655a4b46…
    harness/86f6_fuzz                  86f623f6…
    harness/88ce_fuzz                  88ce8e6b…  Mlipay   (Table II, oob read)
    harness/8aaa_fuzz                  8aaaf201…
    harness/9811_fuzz                  9811c1f6…
    harness/a374_fuzz                  a734eed9…
    harness/e97c_fuzz                  e97c270e…
    pocs/377e_double_fetch_stackov  Table II: SoterApp stack overflow
    pocs/88ce_df_oobr               Table II: Mlipay out-of-bounds read
    pocs/3d08_df_memsetoob          Table II: VSIMApp out-of-bounds write
    pocs/3d08_doublefree            Table II: VSIMApp double free

Both 377e harnesses target the same TA; Exploration fuzzes each TA once, so
`ae/lib/aelib.py:campaign_harnesses` picks the double-fetch one.
