

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <root_dir> <back_dir>"
  exit 1
fi

BACK_DIR=$(realpath $2)
ROOT_DIR=$(realpath $1)

mkdir -p "$BACK_DIR/suspicious_inputs_covs"

BACK_DIR="$BACK_DIR/suspicious_inputs_covs"

find $ROOT_DIR -path "*out/cov/run:id:*.cov" > "$ROOT_DIR/.suspicious_inputs_cov_files.txt"
rsync -a --relative --files-from="$ROOT_DIR/.suspicious_inputs_cov_files.txt" ./ "$BACK_DIR"/


find_target_files() {
  find "$GRAPH_DIR" -name "$1" | grep -v "harness_dev" | grep "harness"
}


# for fuzz_dir in $(ls "$BACK_DIR"/vanilla); do
#     base_name=$(basename "$fuzz_dir")
#     abs_name="$BACK_DIR"/vanilla/$fuzz_dir
#     echo "[+] Finding $base_name under $GRAPH_DIR"
#     target=$(find_target_files "$fuzz_dir" "$base_name")
#     if [ -n "$target" ]; then
#       echo "Found target files: $target"
#       cp -r $abs_name/out $target
#     fi
# done



# for fuzz_dir in $(ls "$BACK_DIR"/df_fuzz); do
#     base_name=$(basename "$fuzz_dir")
#     abs_name="$BACK_DIR"/df_fuzz/$fuzz_dir
#     echo "[+] Finding $base_name under $GRAPH_DIR"
#     target=$(find_target_files "$fuzz_dir" "$base_name")
#     if [ -n "$target" ]; then
#       echo "Found target files: $target"
#       cp -r $abs_name/df_fuzz $target
#     fi
# done


# for fuzz_dir in $(ls "$BACK_DIR"/harness); do
#     base_name=$(basename "$fuzz_dir")
#     abs_name="$BACK_DIR"/harness/$fuzz_dir/suspicious_inputs_replay
#     if [ ! -d "$abs_name" ]; then
#         echo "[-] $abs_name does not exist"
#         continue
#     fi

#     echo "[+] Finding $base_name under $GRAPH_DIR"
#     target=$(find_target_files "$fuzz_dir" "$base_name")
#     if [ -n "$target" ]; then
#       echo "Found target files: $target"
#       cp -r $abs_name $target/in
#     fi
# done
