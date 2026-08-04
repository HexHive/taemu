

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <root_dir> <back_dir>"
  echo "Example: $0 /root/TA_GP_emulator /root/bk_ss_cov"
  exit 1
fi

# pv only draws a progress bar; do not fail if it is unavailable
if ! command -v pv >/dev/null 2>&1; then
  apt-get install -y pv >/dev/null 2>&1 || true
fi
if command -v pv >/dev/null 2>&1; then PV="pv -l -s"; else PV=""; fi


BACK_DIR=$(realpath $2)
ROOT_DIR=$(realpath $1)
ts=$(date +%Y%m%d_%H%M%S)

BACK_DIR="$BACK_DIR/suspicious_inputs_covs"

mkdir -p "$BACK_DIR"



echo "[1] Finding suspicious_inputs_covs files in $ROOT_DIR"
LIST_FILE="$ROOT_DIR/.suspicious_inputs_cov_files.txt"
find $ROOT_DIR -path "*harness/*/out/cov/run:id:*.cov" > "$LIST_FILE"


TOTAL="$(grep -cve '^[[:space:]]*$' "$LIST_FILE" || true)"

echo "[2] Backing up suspicious_inputs_covs files"
if [ -n "$PV" ]; then FEED="pv -l -s $TOTAL $LIST_FILE"; else FEED="cat $LIST_FILE"; fi
$FEED | while IFS= read -r src; do

  [ -z "$src" ] && continue

  [[ -f "$src" ]] || { echo "[MISSING] $src" >&2; continue; }

  dst="${src/#$ROOT_DIR/$BACK_DIR}"

  mkdir -p "$(dirname "$dst")"
  cp -a -- "$src" "$dst"
done

echo "[Done] size of backup ss coverage files: $(find $BACK_DIR -type f | wc -l)"
echo "[3] Finish the backup for suspicious_inputs_covs to $BACK_DIR"
