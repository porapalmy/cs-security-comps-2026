#!/usr/bin/env bash
set -euo pipefail

SAMPLES_DIR="${SAMPLES_DIR:-/samples}"
GENERATED_DIR="${GENERATED_DIR:-/generated_rules}"
PUBLIC_DIR="${PUBLIC_DIR:-/public_rules}"
RESULTS_DIR="${RESULTS_DIR:-/results}"

MODE="${MODE:-all}"                  # all | generated-only | public-only
MAX_SIZE_MB="${MAX_SIZE_MB:-25}"
TIMEOUT_SEC="${TIMEOUT_SEC:-0}"      # 0 = no timeout
INTEL_PATH="${INTEL_PATH:-/opt/intel.json}"
ENRICH="${ENRICH:-1}"                # 1 = write enriched_summary.json

DATE_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

mkdir -p "$RESULTS_DIR"

RAW_OUT="$RESULTS_DIR/scan_raw.txt"
JSONL_OUT="$RESULTS_DIR/matches.jsonl"
SUMMARY_OUT="$RESULTS_DIR/summary.json"
ENRICHED_OUT="$RESULTS_DIR/enriched_summary.json"
RULE_ERRORS="$RESULTS_DIR/rule_errors.txt"
META_MAP_OUT="$RESULTS_DIR/rule_meta_map.json"

: > "$RAW_OUT"
: > "$JSONL_OUT"
: > "$RULE_ERRORS"

echo "[*] Scan started: $DATE_UTC" | tee -a "$RAW_OUT"
echo "[*] Mode: $MODE" | tee -a "$RAW_OUT"
echo "[*] Max file size: ${MAX_SIZE_MB}MB" | tee -a "$RAW_OUT"
echo "[*] Rule dirs: generated=$GENERATED_DIR public=$PUBLIC_DIR" | tee -a "$RAW_OUT"
echo "[*] Samples dir: $SAMPLES_DIR" | tee -a "$RAW_OUT"

# ---------------- rule discovery ----------------
RULE_FILES=()

add_rules_from_dir () {
  local dir="$1"
  if [ -d "$dir" ]; then
    while IFS= read -r -d '' f; do
      RULE_FILES+=("$f")
    done < <(find "$dir" -type f \( -iname "*.yar" -o -iname "*.yara" \) -print0 | sort -z)
  fi
}

case "$MODE" in
  all)
    add_rules_from_dir "$GENERATED_DIR"
    add_rules_from_dir "$PUBLIC_DIR"
    ;;
  generated-only)
    add_rules_from_dir "$GENERATED_DIR"
    ;;
  public-only)
    add_rules_from_dir "$PUBLIC_DIR"
    ;;
  *)
    echo "[!] Unknown MODE=$MODE (use all|generated-only|public-only)" | tee -a "$RAW_OUT"
    exit 2
    ;;
esac

if [ "${#RULE_FILES[@]}" -eq 0 ]; then
  echo "[!] No rule files found (MODE=$MODE)." | tee -a "$RAW_OUT"
  exit 3
fi

echo "[*] Found ${#RULE_FILES[@]} rule file(s)." | tee -a "$RAW_OUT"

# ---------------- rule compile validation (yarac) ----------------
VALID_RULES=()

for rf in "${RULE_FILES[@]}"; do
  TMP_COMPILED="$(mktemp /tmp/yara-compiled.XXXXXX)"
  if yarac "$rf" "$TMP_COMPILED" >/dev/null 2>>"$RULE_ERRORS"; then
    VALID_RULES+=("$rf")
  else
    echo "[!] Rule failed compile: $rf" | tee -a "$RAW_OUT"
  fi
  rm -f "$TMP_COMPILED" >/dev/null 2>&1 || true
done

if [ "${#VALID_RULES[@]}" -eq 0 ]; then
  echo "[!] All rules failed compilation. See $RULE_ERRORS" | tee -a "$RAW_OUT"
  exit 4
fi

echo "[*] Valid rules: ${#VALID_RULES[@]}" | tee -a "$RAW_OUT"

# ---------------- sample discovery ----------------
mapfile -t SAMPLE_FILES < <(
  find "$SAMPLES_DIR" -type f -size -"${MAX_SIZE_MB}"M -print | sort
)

echo "[*] Sample files (<=${MAX_SIZE_MB}MB): ${#SAMPLE_FILES[@]}" | tee -a "$RAW_OUT"

START_TS="$(date +%s)"

# ---------------- meta map extraction (best-effort) ----------------
# Produces JSON: { "RuleName": { "meta_key": "meta_val", ... }, ... }
build_meta_map () {
  awk '
    function trim(s){ sub(/^[ \t\r\n]+/, "", s); sub(/[ \t\r\n]+$/, "", s); return s }
    BEGIN{
      print "{";
      first_rule=1;
      in_rule=0; in_meta=0;
      rule="";
    }
    /^[ \t]*rule[ \t]+[A-Za-z0-9_]+/{
      rule=$0;
      sub(/^[ \t]*rule[ \t]+/, "", rule);
      sub(/[ \t]*\{.*/, "", rule);
      in_rule=1; in_meta=0;

      if (!first_rule) print ",";
      first_rule=0;

      printf "\"%s\":{", rule;
      first_meta=1;
      next
    }
    in_rule && /^[ \t]*meta[ \t]*:/ { in_meta=1; next }
    in_rule && in_meta && /^[ \t]*strings[ \t]*:/ { in_meta=0; next }
    in_rule && in_meta && /^[ \t]*condition[ \t]*:/ { in_meta=0; next }

    in_rule && in_meta {
      line=$0;
      if (index(line, "=")>0) {
        split(line, parts, "=");
        k=trim(parts[1]);
        v=trim(parts[2]);

        # strip trailing comments
        sub(/\/\*.*\*\//, "", v);
        v=trim(v);

        # strip trailing comma
        sub(/,[ \t]*$/, "", v);

        # remove surrounding quotes if present
        if (v ~ /^"/) { sub(/^"/, "", v); sub(/"$/, "", v); }

        if (k != "" && v != "") {
          if (!first_meta) printf ",";
          first_meta=0;

          # minimal JSON escaping
          gsub(/\\/,"\\\\",v);
          gsub(/"/,"\\\"",v);

          printf "\"%s\":\"%s\"", k, v;
        }
      }
      next
    }

    # safer rule close: only when not in meta and line is exactly a closing brace
    in_rule && !in_meta && /^[ \t]*\}[ \t]*$/{
      printf "}";
      in_rule=0; in_meta=0; rule="";
      next
    }

    END{ print "\n}"; }
  ' "${VALID_RULES[@]}" > "$META_MAP_OUT" 2>/dev/null || echo "{}" > "$META_MAP_OUT"
}

build_meta_map
# ensure valid JSON (avoid jq failures later)
jq -e . "$META_MAP_OUT" >/dev/null 2>&1 || echo "{}" > "$META_MAP_OUT"

# ---------------- scanning ----------------
scan_one () {
  local rulefile="$1"
  local target="$2"
  if [ "$TIMEOUT_SEC" -gt 0 ] && command -v timeout >/dev/null 2>&1; then
    timeout "$TIMEOUT_SEC" yara "$rulefile" "$target"
  else
    yara "$rulefile" "$target"
  fi
}

MATCH_COUNT=0
ERROR_COUNT=0

for rf in "${VALID_RULES[@]}"; do
  for f in "${SAMPLE_FILES[@]}"; do
    OUT=""
    if OUT="$(scan_one "$rf" "$f" 2>&1)"; then
      if [ -n "$OUT" ]; then
        while IFS= read -r line; do
          # expected: "<rule_name> <file_path>"
          echo "$line" >> "$RAW_OUT"

          RULE_NAME="$(echo "$line" | awk '{print $1}')"
          FILE_PATH="$(echo "$line" | awk '{print $2}')"

          # enrichment sources
          INTEL_OBJ="$(
            if [ -f "$INTEL_PATH" ]; then
              jq -c --arg r "$RULE_NAME" '.[$r] // {}' "$INTEL_PATH" 2>/dev/null || echo '{}'
            else
              echo '{}'
            fi
          )"

          META_OBJ="$(jq -c --arg r "$RULE_NAME" '.[$r] // {}' "$META_MAP_OUT" 2>/dev/null || echo '{}')"

          # derive fields (intel overrides meta)
          CONF="$(echo "$INTEL_OBJ" | jq -r '.confidence // empty' 2>/dev/null || true)"
          [ -z "$CONF" ] && CONF="$(echo "$META_OBJ" | jq -r '.confidence // empty' 2>/dev/null || true)"
          [ -z "$CONF" ] && CONF="unknown"

          FAMILY="$(echo "$INTEL_OBJ" | jq -r '.family // empty' 2>/dev/null || true)"
          [ -z "$FAMILY" ] && FAMILY="$(echo "$META_OBJ" | jq -r '.family // empty' 2>/dev/null || true)"
          [ -z "$FAMILY" ] && FAMILY="unknown"

          CATEGORY="$(echo "$INTEL_OBJ" | jq -r '.category // empty' 2>/dev/null || true)"
          [ -z "$CATEGORY" ] && CATEGORY="$(echo "$META_OBJ" | jq -r '.category // empty' 2>/dev/null || true)"
          [ -z "$CATEGORY" ] && CATEGORY="unknown"

          # safe verdict language
          VERDICT="suspicious"
          if [ "$CONF" = "high" ]; then VERDICT="likely_malicious"; fi
          if [ "$CATEGORY" = "TestRule" ] || [ "$FAMILY" = "Test" ]; then VERDICT="test_match"; fi

          jq -nc \
            --arg ts "$DATE_UTC" \
            --arg rule "$RULE_NAME" \
            --arg file "$FILE_PATH" \
            --arg rulefile "$rf" \
            --arg verdict "$VERDICT" \
            --arg confidence "$CONF" \
            --arg family "$FAMILY" \
            --arg category "$CATEGORY" \
            --argjson intel "$INTEL_OBJ" \
            --argjson meta "$META_OBJ" \
            '{
              timestamp:$ts,
              rule:$rule,
              file:$file,
              rulefile:$rulefile,
              verdict:$verdict,
              confidence:$confidence,
              family:$family,
              category:$category,
              intel:$intel,
              meta:$meta
            }' >> "$JSONL_OUT"

          MATCH_COUNT=$((MATCH_COUNT+1))
        done <<< "$OUT"
      fi
    else
      ERROR_COUNT=$((ERROR_COUNT+1))
      echo "[!] YARA error rulefile=$rf file=$f :: $OUT" | tee -a "$RAW_OUT"
    fi
  done
done

END_TS="$(date +%s)"
ELAPSED="$((END_TS-START_TS))"

# ---------------- summaries ----------------
RULE_COUNTS_JSON="$(jq -s '
  group_by(.rule) | map({rule: .[0].rule, count: length}) | sort_by(-.count)
' "$JSONL_OUT" 2>/dev/null || echo "[]")"

FILE_COUNTS_JSON="$(jq -s '
  group_by(.file) | map({file: .[0].file, count: length}) | sort_by(-.count)
' "$JSONL_OUT" 2>/dev/null || echo "[]")"

jq -nc \
  --arg started "$DATE_UTC" \
  --arg mode "$MODE" \
  --arg samples_dir "$SAMPLES_DIR" \
  --arg generated_dir "$GENERATED_DIR" \
  --arg public_dir "$PUBLIC_DIR" \
  --argjson rule_files_count "${#VALID_RULES[@]}" \
  --argjson sample_files_count "${#SAMPLE_FILES[@]}" \
  --argjson matches "$MATCH_COUNT" \
  --argjson errors "$ERROR_COUNT" \
  --argjson elapsed_sec "$ELAPSED" \
  --argjson by_rule "$RULE_COUNTS_JSON" \
  --argjson by_file "$FILE_COUNTS_JSON" \
  '{
    started:$started,
    mode:$mode,
    samples_dir:$samples_dir,
    generated_dir:$generated_dir,
    public_dir:$public_dir,
    valid_rule_files: $rule_files_count,
    sample_files_scanned: $sample_files_count,
    total_matches: $matches,
    total_errors: $errors,
    elapsed_sec: $elapsed_sec,
    matches_by_rule: $by_rule,
    matches_by_file: $by_file
  }' > "$SUMMARY_OUT"

if [ "$ENRICH" = "1" ]; then
  # “report-like” output from JSONL stream.
  # Dedupe hit entries by rule name per file (prevents duplicate fake_sample hits from multiple files).
  jq -s '
    def uniq: unique;
    {
      started: (.[0].timestamp // null),
      disclaimer: "YARA matches are pattern matches (signals), not definitive proof of malware. Treat matches as suspicious/likely malicious based on confidence and validate with additional analysis.",
      totals: {
        events: length,
        unique_files: (map(.file) | uniq | length),
        unique_rules: (map(.rule) | uniq | length)
      },
      findings: (
        group_by(.file) | map({
          file: .[0].file,
          hits: (
            map({
              rule: .rule,
              verdict: .verdict,
              confidence: .confidence,
              family: .family,
              category: .category,
              typical_behaviors: (.intel.typical_behaviors // []),
              notes: (.intel.notes // "")
            })
            | unique_by(.rule)
          )
        })
      )
    }
  ' "$JSONL_OUT" > "$ENRICHED_OUT" 2>/dev/null || {
    # if there were 0 matches, write a minimal enriched output
    jq -nc --arg started "$DATE_UTC" '{
      started:$started,
      disclaimer:"YARA matches are pattern matches (signals), not definitive proof of malware. Treat matches as suspicious/likely malicious based on confidence and validate with additional analysis.",
      totals:{events:0, unique_files:0, unique_rules:0},
      findings:[]
    }' > "$ENRICHED_OUT"
  }
fi

echo "[*] Scan finished. matches=$MATCH_COUNT errors=$ERROR_COUNT elapsed=${ELAPSED}s" | tee -a "$RAW_OUT"
echo "[*] Outputs:" | tee -a "$RAW_OUT"
echo "    - $RAW_OUT" | tee -a "$RAW_OUT"
echo "    - $JSONL_OUT" | tee -a "$RAW_OUT"
echo "    - $SUMMARY_OUT" | tee -a "$RAW_OUT"
echo "    - $RULE_ERRORS" | tee -a "$RAW_OUT"
echo "    - $META_MAP_OUT" | tee -a "$RAW_OUT"
[ "$ENRICH" = "1" ] && echo "    - $ENRICHED_OUT" | tee -a "$RAW_OUT"