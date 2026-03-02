#!/bin/bash
set -euo pipefail

BASE_SAMPLES="/home/ubuntu/malware-lab/samples/extracted/phishing"
YARALAB_ROOT="$(pwd)"                          # run from ~/yara-lab
SAMPLES_DEST="$YARALAB_ROOT/samples_repo"      # unified
RULES_DEST="$YARALAB_ROOT/rule_library/generated"  # unified

AUTHOR="Comps Team Malware Lab"
LABEL_SUFFIX="auto"

# be careful: phishing kits often bundle common libs; exclude obvious noise
EXCLUDE_REGEX='(jquery|bootstrap|tailwind|react|angular|vue|lodash|moment|axios|webpack|bundle|vendor|min\.js$|fontawesome|normalize|swiper|chart|datatables|morris|raphael|adminlte)'

mkdir -p "$SAMPLES_DEST" "$RULES_DEST"

shopt -s nullglob
for src in "$BASE_SAMPLES"/*; do
  [[ -d "$src" ]] || continue

  kit="$(basename "$src")"
  kit_norm="$(echo "$kit" \
    | tr '[:upper:]' '[:lower:]' \
    | tr -c '[:alnum:]_' '_' \
    | sed -E 's/^_+//; s/_+$//; s/_+/_/g')"

  name="phish__${kit_norm}"
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

  # Copy kit files (PHP/HTML are primary; include JS/CSS but filter noise)
  while IFS= read -r -d '' f; do
    cp --parents "$f" "$target"/
  done < <(
    find "$src" -type f \( \
        -iname '*.php' -o -iname '*.phtml' \
        -o -iname '*.html' -o -iname '*.htm' \
        -o -iname '*.js' -o -iname '*.css' \
        -o -iname '*.txt' -o -iname '*.json' \
      \) \
      ! -path '*/node_modules/*' \
      ! -path '*/vendor/*' \
      ! -path '*/assets/vendor/*' \
      ! -iname '*.min.js' \
      -print0 \
    | tr '\0' '\n' \
    | grep -Evi "$EXCLUDE_REGEX" \
    | tr '\n' '\0'
  )

  # Must have at least 2 files (yarGen requirement)
  file_count="$(find "$target" -type f | wc -l | tr -d ' ')"
  if [[ "$file_count" -lt 2 ]]; then
    echo "[!] only $file_count files copied for $name — skipping"
    continue
  fi

  # Must have at least one php/html (avoid generating from only css/js noise)
  if ! find "$target" -type f \( -iname '*.php' -o -iname '*.html' -o -iname '*.htm' \) | grep -q .; then
    echo "[!] no PHP/HTML in $name after filtering — skipping"
    continue
  fi

  # Run yarGen; if it fails, continue to next kit (don’t stop whole run)
  if ! docker compose run --rm --user 0:0 yargen python yarGen.py \
        -m "/opt/mal/$name" \
        -o "/opt/out/$name/${name}_${LABEL_SUFFIX}.yar" \
        -a "$AUTHOR" \
        -r "$name phishing_kit $LABEL_SUFFIX gen" \
        --score
  then
    echo "[!] yarGen failed for $name — continuing"
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