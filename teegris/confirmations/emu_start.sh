#!/bin/bash
# emu_start.sh <uuid> <logname> [extra emulate args...]
# Launches the ta_emu container detached, running the given TEEGRIS TA in
# interactive mode, with all emulator output teed to
# teegris/confirmations/_logs/<logname>.log (host-visible via the bind mount).
# Waits until :1337 is listening (CreateEntryPoint done) or the container dies.
set -u
UUID="$1"
LOG="$2"
shift 2
EXTRA="$*"
REPO=/home/lamb/opt/TA_GP_emulator
LOGREL="teegris/confirmations/_logs/${LOG}.log"

docker rm -f emu >/dev/null 2>&1
: > "${REPO}/${LOGREL}"   # truncate host-side

docker run -d --rm --name emu --network host \
  -v "${REPO}":/srv -w /srv/emulator \
  -v /dev/shm:/dev/shm --ipc=host --shm-size=100g \
  ta_emu bash -c "cp ../teegris/tas/${UUID}.ta rootfs/ && cp ../teegris/tas/${UUID}.json rootfs/ && exec python3 -m emulate rootfs/${UUID}.ta --fuzz_harness /dev/null ${EXTRA} > /srv/${LOGREL} 2>&1" >/dev/null

for i in $(seq 1 40); do
  if ! docker ps --format '{{.Names}}' | grep -q '^emu$'; then
    echo "EMU_DIED after ${i}s"; tail -20 "${REPO}/${LOGREL}"; exit 1
  fi
  if ss -ltn 2>/dev/null | grep -q ':1337'; then
    echo "EMU_READY after ${i}s (uuid=${UUID} log=${LOGREL})"; exit 0
  fi
  sleep 1
done
echo "EMU_TIMEOUT (no :1337 after 40s)"; tail -20 "${REPO}/${LOGREL}"; exit 1
