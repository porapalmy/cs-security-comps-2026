#!/bin/bash
set -euo pipefail

BASE_SAMPLES="/home/ubuntu/malware-lab/samples/extracted/javascript"
YARALAB_ROOT="$(pwd)"  # run this from ~/yara-lab
SAMPLES_DEST="$YARALAB_ROOT/samples_repo"
RULES_DEST="$YARALAB_ROOT/rule_library/generated"

AUTHOR="Comps Team Malware Lab"
LABEL_SUFFIX="auto"

# basic library / noise filters (tune as you like)
EXCLUDE_REGEX='(jquery|bootstrap|react|angular|vue|lodash|moment|axios|webpack|bundle|vendor|min\.js$)'

mkdir -p "$SAMPLES_DEST" "$RULES_DEST"

shopt -s nullglob
for src in "$BASE_SAMPLES"/*; do
  [[ -d "$src" ]] || continue

  name="$(basename "$src" | tr '[:upper:]' '[:lower:]' | tr -c '[:alnum:]_' '_')"
  target="$SAMPLES_DEST/$name"
  outdir="$RULES_DEST/$name"
  outfile="$outdir/${name}_${LABEL_SUFFIX}.yar"

  echo
  echo "=== processing: $name ==="
  echo "src: $src"
  echo "dst: $target"
  echo "out: $outfile"

  rm -rf "$target"
  mkdir -p "$target" "$outdir"

  # copy JS files, excluding common libraries/minified/vendor-ish names
  # keep directory structure (parents) to preserve context
  while IFS= read -r -d '' f; do
    cp --parents "$f" "$target"/
  done < <(
    find "$src" -type f -iname '*.js' \
      ! -iname '*.min.js' \
      ! -path '*/node_modules/*' \
      -print0 | \
    perl -0pe '' | tr '\0' '\n' | grep -Ev "$EXCLUDE_REGEX" | tr '\n' '\0'
  )

  # if no JS copied, skip
  if ! find "$target" -type f -iname '*.js' | grep -q .; then
    echo "[!] no (non-excluded) JS files found for $name — skipping"
    continue
  fi

  # Generate rules (run as root to avoid UID=10001 write failures)
  docker compose run --rm \
    --user 0:0 \
    -v "$SAMPLES_DEST:/opt/mal:ro" \
    -v "$RULES_DEST:/opt/out:rw" \
    yargen python yarGen.py \
      -m "/opt/mal/$name" \
      -o "/opt/out/$name/${name}_${LABEL_SUFFIX}.yar" \
      -a "$AUTHOR" \
      -r "$name $LABEL_SUFFIX gen" \
      --score

  # quick sanity check
  if [[ -f "$outfile" ]]; then
    echo "[+] wrote: $outfile"
    grep -E '^rule ' "$outfile" | head -n 5 || true
  else
    echo "[!] expected output missing: $outfile"
  fi
done

echo
echo "all done"