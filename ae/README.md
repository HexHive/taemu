The artifact appendix — claims, requirements, how to run each experiment,
scaling knobs and what cannot be reproduced — is the README in the repository
root: [`../README.md`](../README.md).

This directory is the evaluation harness itself:

    ae.sh              the only thing you run on the host
    ae_ondevice.sh     Table III, needs phones over adb (§6 of ../README.md)
    config.env         budgets and the AE_* knobs (§7)
    Dockerfile         the controller image, built on top of ../Dockerfile
    experiments/       one driver per experiment, plus the five stage_*.py of e1
    lib/               aelib.py (harness discovery, docker, reports), tables.py, common.sh
    data/              dataset.json (Table I's dataset), paper_tables.json
                       (the paper's numbers), vulns.json (Table II), removed_tas.txt
    prebuilt/ondevice/ the nine PoCs, prebuilt for arm64
    results/           created by a run; removed by ./ae.sh clean
