#!/usr/bin/env bash

set -ue

DEBUG=0

unset PYTHONPATH

IN=${IN:-/data}
echo $@
TA=${1}
TA_PATH="/teegris_tas/$TA"
TIMEOUT=300

PROJECT="GhidraProject"

GHIDRA=/ghidra

# keep track of time

# run in production mode
GHIDRA_PROJ=/tmp/ghidraproj
mkdir -p ${GHIDRA_PROJ}
timeout ${TIMEOUT} ${GHIDRA}/support/analyzeHeadless \
	  $GHIDRA_PROJ \
	  SharingCaringTmpProj \
	  -import ${TA_PATH} \
	  -scriptPath /src/ghidra_scripts/ \
	  -preScript FunctionIDHeadlessPrescript.java \
	  -postScript teegris_funcs.py \
