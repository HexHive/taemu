#!/bin/sh

./bk_suspicious_inputs_covs.sh /root/TA_GP_emulator /root/TA_GP_emulator/bk_ss_cov
uv run main.py --path /root/TA_GP_emulator --ss_cov_rdir /root/TA_GP_emulator/bk_ss_cov --regen_coverage
