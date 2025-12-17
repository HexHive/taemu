#!/usr/bin/env bash

YELLOW=$'\e[1;33m'
CYAN=$'\e[1;36m'
GREEN=$'\e[1;32m'
RED=$'\e[1;31m'
RESET=$'\e[0m'


if [ -z "$1" ]; then 
    echo "Usage: ./clean_fuzz_trace.sh <path to harness folder| . for all harnesses> [--force]"
    exit 0
fi


if [ "$1" == "." ]; then
    for harness in $(ls -d /root/TA_GP_emulator/*/harness/*/); do
        if [ -d "$harness" ]; then
            echo "Cleaning fuzz traces in $harness"

            ./clean_fuzz_trace.sh $harness $2
        fi
    done
    echo -e "${YELLOW} ============================== ${RESET}"
    echo -e "${YELLOW} Current left files: ${RESET}"
    find . -type f -path '*suspicious*'
    find . -type f -path '*df_fuzz/*'
    echo -e "${YELLOW} ============================== ${RESET}"
    exit 0
fi

in_path=`realpath $1`
echo "Cleaning fuzz traces in $in_path ${2:+with force}"
if [ -d "$in_path" ]; then
    fuzz_out="$in_path/out"
    fuzz_in="$in_path/in"
    fuzz_suspicious_inputs="$in_path/in/suspicious_inputs"
    fuzz_suspicious_inputs_replay="$in_path/in/suspicious_inputs_replay"
    fuzz_df_dir="$in_path/df_fuzz"
    ql_log=$(dirname $(realpath $0))/ql-emulator.log*
else
    echo "Provided path $in_path is not a directory"
    exit 1
fi


if [ -z "${fuzz_out:-}" ] || [ -z "${fuzz_in:-}" ]; then
    echo -e "${RED}Error:${RESET} fuzz_out or fuzz_in is not set."
    exit 1
fi

echo -e "
[-]Cleaning fuzz traces of the following directories:\n
 ${CYAN}$fuzz_out${RESET}\n
 ${CYAN}$fuzz_in${RESET}\n
 ${CYAN}$fuzz_suspicious_inputs${RESET}\n
 ${CYAN}$fuzz_suspicious_inputs_replay${RESET}\n
 ${CYAN}$ql_log${RESET}\n
 ${CYAN}$fuzz_df_dir${RESET}\n
[!]"

# check each directory one by one, and confirm whether to delete it
for dir in "$fuzz_out" "$fuzz_in" "$fuzz_suspicious_inputs" "$fuzz_suspicious_inputs_replay" "$ql_log" "$fuzz_df_dir"; do
    if [ -d "$dir" ]; then
        echo -e "${CYAN}$dir${RESET} exists"
        if [ -z "$2" ] || [ "$2" != "--force" ]; then
            read -r -p "Are you sure you want to delete all files of ${YELLOW} $dir? (y/N): ${RESET}" user_input
            user_input="${user_input:-n}"
            user_input_lower=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')
            case "$user_input_lower" in
                y|yes)
                    echo -e "${GREEN}Proceeding with cleanup...${RESET}"
                    rm -rf -- "${dir:?}/"* || true
                    echo -e "${GREEN}Cleanup finished.${RESET}"
                    ;;
                n|no)
                    echo -e "${RED}Aborting cleanup and continuing with the next target.${RESET}"
                    ;;
            esac
        else
            echo -e "${GREEN}Proceeding with cleanup...${RESET}"
            rm -rf -- "${dir:?}/"* || true
            echo -e "${GREEN}Cleanup finished.${RESET}"
        fi
    else
        echo -e "${RED}$dir${RESET} does not exist"
    fi
done