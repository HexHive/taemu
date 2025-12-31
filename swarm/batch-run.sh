#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <minutes-for-original-fuzzing> <minutes-for-df-fuzzing>"
    exit 1
fi

MINUTES_ORIGINAL_FUZZING=$1
MINUTES_DF_FUZZING=$2

start_time=$(date +%s)
echo "Overview:"
echo " - Run original fuzzing for $MINUTES_ORIGINAL_FUZZING minutes"
echo " - Deduplication"
echo " - Run df fuzzing for $MINUTES_DF_FUZZING minutes"


echo "Continue? (y/n)"
read -p " " CONTINUE
if [ "$CONTINUE" != "y" ]; then
    echo "Exiting..."
    exit 1
fi

cd /root/TA_GP_emulator/swarm
echo "1. Running original fuzzing..."
echo "y" | cargo run -- -t .. -f /root/TA_GP_emulator/emulator/fuzz.sh -d $MINUTES_ORIGINAL_FUZZING > "org-fuzz-output$(date +day%d-%H_%M_%S).log" 2>&1

echo "2. Deduplicating original fuzzing and generating suspicious_inputs_replay..."
cd /root/TA_GP_emulator
echo -e "y\ny" | python3 eval/deduplicate.py --mode coverage --enable-del

reset

cd /root/TA_GP_emulator/swarm
echo "3. Running df fuzzing..."
echo "y" | cargo run -- -t .. -f /root/TA_GP_emulator/emulator/df_fuzz.sh -d $MINUTES_DF_FUZZING -s > "df-fuzz-output$(date +day%d-%H_%M_%S).log" 2>&1

end_time=$(date +%s)
duration=$((end_time - start_time))
echo "Total time: $((duration / 60)) minutes $((duration % 60)) seconds"
echo "Done!"
