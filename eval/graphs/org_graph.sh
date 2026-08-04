#!/bin/sh

uv run main.py --path /root/TA_GP_emulator/ --ss_cov_rdir $2 --fuzz_mode ORG --show_rate --tees $1 --org_group_field tee
