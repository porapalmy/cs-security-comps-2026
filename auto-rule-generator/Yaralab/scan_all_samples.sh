#!/bin/bash
set -euo pipefail

BASE_SAMPLES="/home/ubuntu/malware-lab/samples/extracted/php"
YARALAB_ROOT="$(pwd)"                               # run from ~/yara-lab
SAMPLES_DEST="$YARALAB_ROOT/samples_repo"           # unified
RULES_DEST="$YARALAB_ROOT/rule_library/generated"   # unified

AUTHOR="Comps Team Malware Lab"
LABEL_SUFFIX="auto"

mkdir -p "$SAMPLES_DEST" "$RULES_DEST"

norm_name() {
  echo "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | tr -c '[:alnum:]_' '_' \
    | sed -E 's/^_+//; s/_+$//; s/_+/_/g'
}

# Light content sniffing to classify loose files
classify_file() {
  local f="$1"

  # If file is binary-ish, classify as bin
  if LC_ALL=C grep -qP '[\x00-\x08\x0B\x0C\x0E-\x1F]' "$f" 2>/dev/null; then
    echo "bin"
    return
  fi

  # Read first ~50KB for signatures (fast enough)
  local headtxt
  headtxt="$(head -c 50000 "$f" 2>/dev/null || true)"

  if echo "$headtxt" | grep -qiE '<\?php|<\?=|\$_(post|get|server|cookie|request)|base64_decode\(|gzinflate\(|eval\(|assert\(|preg_replace\(.*/e'; then
    echo "php"
  elif echo "$headtxt" | grep -qiE '<html|<!doctype html|<form|type=["'\'']password["'\'']'; then
    echo "html"
  elif echo "$headtxt" | grep -qiE 'function\s*\(|document\.|window\.|XMLHttpRequest|fetch\('; then
    echo "js"
  else
    echo "other"
  fi
}

echo "[*] 1) Copying + bucketing samples into samples_repo/php__* ..."

# 1) Handle subfolders as families
shopt -s nullglob
for d in "$BASE_SAMPLES"/*/; do
  [[ -d "$d" ]] || continue
  folder="$(basename "$d")"
  fam="php__$(norm_name "$folder")"
  dest="$SAMPLES_DEST/$fam"
  rm -rf "$dest"
  mkdir -p "$dest"
  echo "  [+] folder family: $fam"

  # Copy everything in the folder, preserving structure
  # (yarGen is content-driven; extensions don't matter much)
  rsync -a --delete "$d"/ "$dest"/
done

# 2) Handle loose files in root
loose_dir="$BASE_SAMPLES"
for f in "$loose_dir"/*; do
  [[ -f "$f" ]] || continue
  t="$(classify_file "$f")"
  fam="php__loose__${t}"
  dest="$SAMPLES_DEST/$fam"
  mkdir -p "$dest"

  # avoid name collisions
  bn="$(basename "$f")"
  bn_norm="$(norm_name "$bn")"
  # attach a short hash prefix for uniqueness
  hp="$(sha256sum "$f" | awk '{print substr($1,1,12)}')"
  cp -a "$f" "$dest/${bn_norm}__${hp}"
done

echo
echo "[*] 2) Generating YARA rules for each php__* family ..."

# Generate rules for each family; keep going on failures
for famdir in "$SAMPLES_DEST"/php__*; do
  [[ -d "$famdir" ]] || continue

  fam="$(basename "$famdir")"
  outdir="$RULES_DEST/$fam"
  outfile="$outdir/${fam}_${LABEL_SUFFIX}.yar"
  mkdir -p "$outdir"

  file_count="$(find "$famdir" -type f | wc -l | tr -d ' ')"
  if [[ "$file_count" -lt 2 ]]; then
    echo "  [!] $fam has only $file_count file(s) — skipping (yarGen needs >=2)"
    continue
  fi

  echo
  echo "=== yarGen: $fam ($file_count files) ==="

  if ! docker compose run --rm --user 0:0 yargen python yarGen.py \
        -m "/opt/mal/$fam" \
        -o "/opt/out/$fam/${fam}_${LABEL_SUFFIX}.yar" \
        -a "$AUTHOR" \
        -r "$fam php_mixed $LABEL_SUFFIX gen" \
        --score
  then
    echo "[!] yarGen failed for $fam — continuing"
    continue
  fi

  if [[ -f "$outfile" ]]; then
    echo "[+] wrote: $outfile"
    grep -E '^rule ' "$outfile" | head -n 5 || true
  else
    echo "[!] expected output missing: $outfile"
  fi
done

echo
echo "all done"