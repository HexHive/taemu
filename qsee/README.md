# QSEE

TA corpus, harnesses and PoCs for Qualcomm's QSEE. See
[`../README.md`](../README.md) §1 for what each subdirectory holds and §5 for
how the experiments use them.

## Provenance

| | |
|---|---|
| handset | OnePlus 12R, Android 15 |
| build | `OnePlus/CPH2609EEA/OP5D35L1:15/TP1A.220905.001/U.R4T3.1c7e5be_1_2:user/release-keys` |

Table I: 4 GlobalPlatform TAs, 3 of which operate directly on shared memory.

## Contents

    tas/                  4 TAs, with .json entry-point offsets and bbs/ CFGs
    harness/3d08_fuzz     3D08821C…  VSIMApp (Table II, oob write + double free;
                          the same TA also ships on MiTEE)
    harness/876b_fuzz     876BFD99…
    harness/a985_fuzz     A985D3EB…
    pocs/a985_test        Table III: the QSEE zero-copy probe — the TA returns
                          -5 when both fetches agree and -24 only when they
                          disagree (Listing 6, §6 of ../README.md)
