

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <root_dir> <back_dir>"
  echo "Example: $0 /root/TA_GP_emulator /root/bk_ss_cov"
  exit 1
fi

command -v pv && echo "pv is installed" || apt-get install -y pv


BACK_DIR=$(realpath $2)
ROOT_DIR=$(realpath $1)
ts=$(date +%Y%m%d_%H%M%S)

BACK_DIR="$BACK_DIR/$ts/suspicious_inputs_covs"

mkdir -p "$BACK_DIR"



echo "[1] Finding suspicious_inputs_covs files in $ROOT_DIR"
LIST_FILE="$ROOT_DIR/.suspicious_inputs_cov_files.txt"
find $ROOT_DIR -path "*harness/*/out/cov/run:id:*.cov" > "$LIST_FILE"


TOTAL="$(grep -cve '^[[:space:]]*$' "$LIST_FILE" || true)"

echo "[2] Backing up suspicious_inputs_covs files"
pv -l -s "$TOTAL" "$LIST_FILE" | while IFS= read -r src; do

  [ -z "$src" ] && continue

  [[ -f "$src" ]] || { echo "[MISSING] $src" >&2; continue; }

  dst="${src/#$ROOT_DIR/$BACK_DIR}"

  mkdir -p "$(dirname "$dst")"
  cp -a -- "$src" "$dst"
done

echo "[Done] size of backup ss coverage files: $(find $BACK_DIR -type f | wc -l)"
echo "[3] Finish the backup for suspicious_inputs_covs to $BACK_DIR"