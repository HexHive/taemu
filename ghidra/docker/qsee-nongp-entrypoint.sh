#!/usr/bin/env bash

set -ue

DEBUG=0

unset PYTHONPATH
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Dlog4j2.disableJmx=true -XX:-UseContainerSupport"

IN=${IN:-/data}
echo $@
TA=$1
TIMEOUT=3000


GHIDRA=/ghidra

HEADLESS_ARGS=()
if [ -n "${GHIDRA_MAX_CPU:-}" ]; then
  HEADLESS_ARGS+=(-max-cpu "${GHIDRA_MAX_CPU}")
fi

# keep track of time

GHIDRA_PROJ=/mnt/.ghidra-projects/qsee_nongp
PROJECT="GhidraProject"

mkdir -p ${GHIDRA_PROJ}
timeout --foreground ${TIMEOUT} ${GHIDRA}/support/analyzeHeadless \
  $GHIDRA_PROJ \
  $PROJECT \
  -process ${TA} \
  -noanalysis \
  -scriptPath /src/ghidra_scripts/ \
  "${HEADLESS_ARGS[@]}" \
  -postScript qsee_nongp_funcs.py
