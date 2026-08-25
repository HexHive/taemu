#!/bin/sh

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 13/14/15 hex1X_X"
  exit 1
fi

mkdir -p "multi_graph_data/$2"

scp -r "root@hexhive0$1.iccluster.epfl.ch:/root/TA_GP_emulator/eval/graphs/rawinfo/" "multi_graph_data/$2"
scp -r "root@hexhive0$1.iccluster.epfl.ch:/root/TA_GP_emulator/eval/graphs/df_rawinfo/" "multi_graph_data/$2"
