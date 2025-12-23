#!/bin/bash

echo "y" | cargo run -- -t .. -f /root/TA_GP_emulator/emulator/fuzz.sh -d 60 > "fuzz-output$(date +%H_%M_%S).log" 2>&1
echo "y" | cargo run -- -t .. -f /root/TA_GP_emulator/emulator/df_fuzz.sh -d 15 -s -m 28  > "df-output$(date +%H_%M_%S).log" 2>&1
