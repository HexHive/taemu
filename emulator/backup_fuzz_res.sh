#!/bin/bash

dest="/root/backup_df_results"
mkdir -p "$dest"

timestamp=$(date +%Y%m%d%H%M%S)
mkdir -p "$dest/$timestamp"

read -p "Are you sure you want to backup fuzz results? (y/N): " user_input
user_input="${user_input:-n}"
user_input_lower=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')
case "$user_input_lower" in
    y|yes)
        echo "Proceeding with backup..."
        ;;
    n|no)
        echo "Aborting backup..."
        exit 0
        ;;
esac

find /root/TA_GP_emulator -type d -name "suspicious_inputs" | while read src; do
    parent=$(basename "$(dirname "$(dirname "$src")")")
    pparent=$(basename "$(dirname "$(dirname "$(dirname "$src")")")")
    mkdir -p "$dest/$timestamp/$pparent/$parent"
    cp -r "$src" "$dest/$timestamp/$pparent/$parent/"
done

echo "finish the backup for suspicious_inputs"

find /root/TA_GP_emulator -type d -name "df_fuzz" | while read src; do
    parent=$(basename "$(dirname "$src")")

    mkdir -p "$dest/$timestamp/df_fuzz/$parent"
    cp -r "$src" "$dest/$timestamp/df_fuzz/$parent/"
done


echo "finish the backup for df_fuzz"

find /root/TA_GP_emulator -type d -name "suspicious_inputs_replay" | while read src; do
    parent=$(basename "$(dirname "$(dirname "$src")")")
    pparent=$(basename "$(dirname "$(dirname "$(dirname "$src")")")")
    mkdir -p "$dest/$timestamp/$pparent/$parent"
    cp -r "$src" "$dest/$timestamp/$pparent/$parent/"
done

echo "finish the backup for suspicious_inputs_replay"
echo "Backup completed at $dest/$timestamp"
