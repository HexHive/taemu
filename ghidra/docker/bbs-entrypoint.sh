#!/usr/bin/env bash

set -ue

DEBUG=0

unset PYTHONPATH

IN=${IN:-/data}
echo $@
TA=${1}
TEE=${2}
TA_PATH="/${TEE}_tas/$TA"
TIMEOUT=6000

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
	  -postScript coverage_bbs.py \
      ++tee ${TEE}
