#!/usr/bin/env bash
# Wraps emulator + potentially gdb in tmux panes.
# Usage: ./tmux.sh <path to ta> [gdb]

CONNECT_GDB=false

for arg in "$@"; do
  case "$arg" in
  gdb)
    CONNECT_GDB=true
    ;;
  *)
    TA_PATH="$arg"
    ;;
  esac
done

[ -z "$TA_PATH" ] && echo "Usage: $0 <path to ta> [gdb]" && exit 1
[ ! -f "$TA_PATH" ] && echo "File $TA_PATH not found" && exit 1

# Check we are in TMUX
[ -z "$TMUX" ] && echo "Not in TMUX" && exit 1

_DOCKER_RUN="docker compose run --rm --name emu_dbg emulator"
_DOCKER_EXEC="docker compose exec emulator "
EMULATOR_DEBUG="$_DOCKER_RUN ./run.sh ../$TA_PATH"
EM_GDB_ATTACH="$_DOCKER_EXEC gdb-multiarch -ex 'set sysroot emulator/rootfs/' -iex 'set history filename /srv/.gdb_history' "

PANE1=$(tmux display-message -p '#{pane_id}')
tmux split-window -h -t $PANE1 sh -c "$EMULATOR_DEBUG; zsh"
# Wait for emulator to start
until [ "$(docker ps --filter name=emu_dbg --format='{{.State}}')" = "running" ]; do
  sleep 0.5
done

tmux select-pane -t $PANE1
#tmux send-keys "$EM_GDB_ATTACH" C-m
tmux send-keys "$EM_GDB_ATTACH"

# Shell stays behind
#PANE2=$(tmux split-window -P -F "#{pane_id}")
#tmux send-keys -t "$PANE2" "$EMULATOR_DEBUG" C-m
