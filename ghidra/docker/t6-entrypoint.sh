#!/usr/bin/env bash

set -ue

DEBUG=0

unset PYTHONPATH

IN=${IN:-/data}
echo $@
TA=${1}
TA_PATH="/t6_tas/$TA"
TIMEOUT=3000

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
	  -postScript t6_funcs.py \
