#!/usr/bin/env bash

set -ue

DEBUG=0

unset PYTHONPATH
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Dlog4j2.disableJmx=true -XX:-UseContainerSupport"

IN=${IN:-/data}
echo $@
TA=${1}
TEE=${2}
TA_PATH="/${TEE}_tas/$TA"
TIMEOUT=6000

PROJECT="GhidraProject"

GHIDRA=/ghidra
BBS_SCRIPT=${BBS_SCRIPT:-coverage_bbs.py}

HEADLESS_ARGS=()
if [ -n "${GHIDRA_MAX_CPU:-}" ]; then
  HEADLESS_ARGS+=(-max-cpu "${GHIDRA_MAX_CPU}")
fi

# keep track of time

# run in production mode
GHIDRA_PROJ=/tmp/ghidraproj
mkdir -p ${GHIDRA_PROJ}
timeout ${TIMEOUT} ${GHIDRA}/support/analyzeHeadless \
  $GHIDRA_PROJ \
  SharingCaringTmpProj \
  -import ${TA_PATH} \
  -scriptPath /src/ghidra_scripts/ \
  "${HEADLESS_ARGS[@]}" \
  -preScript FunctionIDHeadlessPrescript.java \
  -postScript ${BBS_SCRIPT} \
  ++tee ${TEE}
