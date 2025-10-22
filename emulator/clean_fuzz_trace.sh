#!/usr/bin/env bash

YELLOW=$'\e[1;33m'
CYAN=$'\e[1;36m'
GREEN=$'\e[1;32m'
RED=$'\e[1;31m'
RESET=$'\e[0m'


if [ -z "$1" ]; then 
    echo "Usage: ./clean_fuzz_trace.sh <path to harness folder>"
    exit 0
fi

in_path=`realpath $1`
if [ -d "$in_path" ]; then
    fuzz_out="$in_path/out"
    fuzz_in="$in_path/in"
else
    echo "Provided path $in_path is not a directory"
    exit 1
fi


if [ -z "${fuzz_out:-}" ] || [ -z "${fuzz_in:-}" ]; then
    echo -e "${RED}Error:${RESET} fuzz_out or fuzz_in is not set."
    exit 1
fi

echo -e "Cleaning fuzz traces in ${CYAN}$fuzz_out${RESET} and ${CYAN}$fuzz_in${RESET}"
read -r -p "Are you sure you want to delete all files in ${YELLOW} $fuzz_out and $fuzz_in? (y/N): ${RESET}" user_input
user_input="${user_input:-n}"

user_input_lower=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')

case "$user_input_lower" in
    y|yes)
        echo -e "${GREEN}Proceeding with cleanup...${RESET}"
        rm -rf -- "${fuzz_out:?}/"* "${fuzz_in:?}/"* || true
        echo -e "${GREEN}Cleanup finished.${RESET}"
        ;;
    n|no)
        echo -e "${RED}Aborting cleanup.${RESET}"
        exit 0
        ;;
    *)
        echo -e "${YELLOW}Invalid input. Please enter 'y' or 'n'.${RESET}"
        ;;
esac