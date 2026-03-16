from flask import Flask, request, jsonify
import yara
import os
import re
import socket
import ipaddress
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
import urllib3
import sqlite3 # NEW: For fuzzy database
import ppdeep  # NEW: For fuzzy hash comparison
import concurrent.futures

# Suppress InsecureRequestWarning for scanned sites
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -----------------------------
# SSRF Protection
# -----------------------------
def is_safe_url(url: str) -> bool:
    """SSRF protection: block private/loopback/metadata IPs."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False

        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private or ip_obj.is_loopback:
            return False

        # Cloud metadata IP (AWS)
        if str(ip_obj) == "169.254.169.254":
            return False

        return True
    except Exception:
        return False


app = Flask(__name__)

# -----------------------------
# Fuzzy Search Fallback Function
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "malware_fuzzy.db")
FUZZY_THRESHOLD = 50

def fuzzy_search_fallback(file_content):
    """Checks the SQLite database for similar files if YARA misses."""
    if not os.path.exists(DB_PATH):
        return []
    try:
        # Generate hash for current content
        uploaded_hash = ppdeep.hash(file_content)
        chunk_size = int(uploaded_hash.split(':')[0])
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Optimization: only check similar chunk sizes
        cursor.execute(
            "SELECT * FROM signatures WHERE chunk_size IN (?, ?, ?)", 
            (chunk_size, chunk_size // 2, chunk_size * 2)
        )
        candidates = cursor.fetchall()
        
        fuzzy_matches = []
        for row in candidates:
            score = ppdeep.compare(uploaded_hash, row['fuzzy_hash'])
            if score >= FUZZY_THRESHOLD:
                fuzzy_matches.append({
                    "rule": f"Fuzzy Match: {score}% Similarity",
                    "namespace": "FuzzyDB",
                    "ruleKey": f"fuzzy:{row['id']}",
                    "ruleFile": row['file_name'],
                    "snippets": [f"Known structural variant found at: {row['file_path']}"],
                    "yaraRule": None 
                })
        conn.close()
        return sorted(fuzzy_matches, key=lambda x: x['rule'], reverse=True)
    except Exception as e:
        print(f"[!] Fuzzy Fallback Error: {e}")
        return []

# -----------------------------
# YARA Rule Loading (Folder Mode) - ALL ORIGINAL PRINTS PRESERVED
# -----------------------------
RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
rules = None
rule_sources = {}

def _extract_rule_blocks(yara_text: str):
    pattern = re.compile(r"(?ms)\brule\s+([A-Za-z_]\w*)\b.*?\{.*?\n\}", re.DOTALL)
    for m in pattern.finditer(yara_text):
        name = m.group(1)
        block = m.group(0).strip()
        yield name, block

def load_yara_rules_from_dir(rules_dir: str):
    sources = {}
    valid_filepaths = {}
    bad_files = []
    parsed_blocks = 0

    print(f"[YARA] Loading rules from: {rules_dir}", flush=True)

    if not os.path.isdir(rules_dir):
        print(f"[YARA] Rules directory not found: {rules_dir}", flush=True)
        return None, sources, {
            "total_files": 0,
            "valid_files": 0,
            "skipped_files": 0,
            "skipped": [],
            "parsed_rule_blocks": 0,
        }

    rule_files = []
    for root, _, files in os.walk(rules_dir):
        for fn in files:
            if fn.lower().endswith((".yar", ".yara")):
                rule_files.append(os.path.join(root, fn))

    rule_files.sort()
    total = len(rule_files)
    print(f"[YARA] Discovered {total} rule files", flush=True)

    if total == 0:
        return None, sources, {
            "total_files": 0,
            "valid_files": 0,
            "skipped_files": 0,
            "skipped": [],
            "parsed_rule_blocks": 0,
        }

    for path in rule_files:
        rel = os.path.relpath(path, rules_dir)
        ns = re.sub(r"[^A-Za-z0-9_]+", "_", os.path.splitext(rel)[0])
        try:
            yara.compile(filepath=path)
        except Exception as e:
            bad_files.append({"path": rel, "error": str(e)})
            continue

        valid_filepaths[ns] = path

        try:
            raw = open(path, "r", encoding="utf-8", errors="ignore").read()
            for rule_name, rule_block in _extract_rule_blocks(raw):
                key = f"{ns}:{rule_name}"
                sources[key] = {"text": rule_block, "path": rel, "namespace": ns}
                parsed_blocks += 1
        except Exception as e:
            print(f"[YARA] Failed to read {rel}: {e}", flush=True)

    valid = len(valid_filepaths)
    skipped = len(bad_files)
    stats = {
        "total_files": total,
        "valid_files": valid,
        "skipped_files": skipped,
        "skipped": bad_files,
        "parsed_rule_blocks": parsed_blocks,
    }

    print(f"[YARA] Summary: total={total}, valid={valid}, skipped={skipped}, parsed_blocks={parsed_blocks}", flush=True)

    if skipped:
        print("[YARA] Skipped files (first 20):", flush=True)
        for item in bad_files[:20]:
            print(f"  - {item['path']}: {item['error']}", flush=True)

    if valid == 0:
        print("[YARA] No valid rules compiled.", flush=True)
        return None, sources, stats

    try:
        compiled = yara.compile(filepaths=valid_filepaths)
        print("[YARA] Aggregated ruleset compiled successfully.", flush=True)
        return compiled, sources, stats
    except Exception as e:
        print(f"[YARA] Aggregated compilation error: {e}", flush=True)
        return None, sources, stats

rules, rule_sources, yara_load_stats = load_yara_rules_from_dir(RULES_DIR)

# -----------------------------
# Formatting & Snippets
# -----------------------------
def format_match(m, snippets):
    ns = getattr(m, "namespace", None)
    rule_key = f"{ns}:{m.rule}" if ns else m.rule
    src = rule_sources.get(rule_key)
    return {
        "rule": m.rule,
        "namespace": ns,
        "ruleKey": rule_key,
        "ruleFile": src.get("path") if src else None,
        "snippets": snippets,
        "yaraRule": src.get("text") if src else None,
    }

def build_snippets(decoded_text: str, m, max_snippets: int = 3, context: int = 60):
    snippets = []
    try:
        for string_match in getattr(m, "strings", []):
            for instance in getattr(string_match, "instances", []):
                offset = getattr(instance, "offset", None)
                matched_data = getattr(instance, "matched_data", b"")
                if offset is None: continue
                start = max(0, offset - context)
                end = min(len(decoded_text), offset + len(matched_data) + context)
                snip = decoded_text[start:end].strip()
                if snip and len(snippets) < max_snippets:
                    snippets.append(snip)
                if len(snippets) >= max_snippets: break
            if len(snippets) >= max_snippets: break
    except Exception: pass
    return snippets

@app.route("/api/scan", methods=["POST"])
def scan():
    global rules
    if not rules:
        return jsonify({"score": 0, "matches": [], "details": "Error: YARA rules not loaded."}), 500

    content = b""
    source = ""
    match_details = []
    analysis_log = []

    try:
        # -----------------------------
        # FILE SCAN
        # -----------------------------
        if "file" in request.files:
            f = request.files["file"]
            content = f.read()
            source = f.filename or "uploaded_file"
            decoded_file = content.decode("utf-8", errors="ignore")
            
            # Step 1: Run Original YARA
            matches = rules.match(data=content)
            for m in matches:
                snippets = build_snippets(decoded_file, m)
                match_details.append(format_match(m, snippets))

            # Step 2: Fallback to Fuzzy DB if YARA misses
            if not match_details:
                fuzzy_hits = fuzzy_search_fallback(content)
                if fuzzy_hits:
                    match_details.extend(fuzzy_hits)
                    analysis_log.append(f"🔍 YARA Missed. Fuzzy DB found {len(fuzzy_hits)} structural matches.")

            content_preview = decoded_file[:2000]

        # -----------------------------
        # URL SCAN (HTML + assets)
        # -----------------------------
        elif "url" in request.form:
            url = request.form["url"].strip()
            if not url.startswith(("http://", "https://")): url = "https://" + url
            if not is_safe_url(url): return jsonify({"error": "Security Alert: Restricted IP."}), 403

            source = url
            req_headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, timeout=5, headers=req_headers, verify=False)
            html_content = resp.content
            decoded_html = html_content.decode("utf-8", errors="ignore")
            soup = BeautifulSoup(html_content, "html.parser")

            assets_to_scan = []
            for tag in soup.find_all("script", src=True)[:10]: assets_to_scan.append(("js", tag["src"]))
            for tag in soup.find_all("link", rel="stylesheet", href=True)[:10]: assets_to_scan.append(("css", tag["href"]))

            # Main HTML YARA scan
            for m in rules.match(data=html_content):
                match_details.append(format_match(m, build_snippets(decoded_html, m)))

            content_preview = {"html": decoded_html[:4000], "js": [], "css": []}
            asset_contents_bytes = []

            # PARALLEL FETCHING (Kept Original)
            def process_asset(asset_type, asset_path):
                try:
                    full_url = urljoin(url, asset_path)
                    if not is_safe_url(full_url): return None
                    r = requests.get(full_url, timeout=2, headers=req_headers, verify=False)
                    if r.status_code != 200: return None
                    if len(r.content) > 500 * 1024: return None
                    content_text = r.content.decode("utf-8", errors="ignore")
                    matches_local = rules.match(data=r.content)
                    results_local = []
                    for m in matches_local:
                        snippets = build_snippets(content_text, m)
                        results_local.append(format_match(m, snippets))
                    return {
                        "type": asset_type,
                        "name": asset_path.split("/")[-1] or "asset",
                        "content": content_text[:2000],
                        "matches": results_local,
                        "bytes": r.content,
                    }
                except Exception: return None

            # Your original concurrent loop exactly as requested
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(process_asset, t, p) for t, p in assets_to_scan]
                for future in concurrent.futures.as_completed(futures):
                    data = future.result()
                    if not data: continue
                    if data["matches"]: match_details.extend(data["matches"])
                    if data["type"] == "js":
                        content_preview["js"].append({"name": data["name"], "content": data["content"]})
                    elif data["type"] == "css":
                        content_preview["css"].append({"name": data["name"], "content": data["content"]})
                    asset_contents_bytes.append(data["bytes"])

            content = html_content
            for b in asset_contents_bytes: content += b"\n" + b

            # FUZZY INTEGRATION for URL
            if not match_details:
                fuzzy_hits = fuzzy_search_fallback(content)
                if fuzzy_hits:
                    match_details.extend(fuzzy_hits)
                    analysis_log.append("🔍 YARA Missed. Fuzzy DB found structural site matches.")

        else: return jsonify({"error": "No content provided"}), 400

        # -----------------------------
        # HEURISTIC ANALYSIS (ORIGINAL LINES PRESERVED)
        # -----------------------------
        heuristics_score = 0
        try:
            decoded_content = content.decode("utf-8", errors="ignore")
        except:
            decoded_content = str(content)

        analysis_log.append(f"Extracted content ({len(content)} bytes total)")
        heuristic_details = []

        # Check 1: Suspicious Redirects (Exactly as provided)
        redirect_pattern = re.compile(r'(window\.location\s*=|http-equiv=["\']refresh["\'])', re.IGNORECASE)
        redirect_matches = list(redirect_pattern.finditer(decoded_content))
        if len(redirect_matches) >= 3:
            analysis_log.append(f"❌ Heuristic Failed: Suspicious Redirects ({len(redirect_matches)} redirect patterns found)")
            heuristics_score += 20
            snippets = []
            for rm in redirect_matches[:3]:
                start = max(0, rm.start() - 60)
                end = min(len(decoded_content), rm.end() + 60)
                snippets.append(decoded_content[start:end].strip())
            heuristic_details.append({"rule": "Suspicious Redirects", "snippets": snippets})
        else:
            analysis_log.append("✅ Heuristic Passed: Suspicious Redirects")

        # Check 2: Obfuscation (Exactly as provided)
        obfuscation_markers = ["eval(", "unescape(", "document.write("]
        obf_count = sum(decoded_content.lower().count(m) for m in obfuscation_markers)
        if obf_count >= 8:
            found_markers = [m for m in obfuscation_markers if m in decoded_content.lower()]
            analysis_log.append(f"❌ Heuristic Failed: Eval/Obfuscation ({obf_count} occurrences of: {', '.join(found_markers)})")
            heuristics_score += 15
            obf_snippets = []
            obf_re = re.compile(r"(eval\(|unescape\(|document\.write\()", re.IGNORECASE)
            for om in list(obf_re.finditer(decoded_content))[:3]:
                start = max(0, om.start() - 60)
                end = min(len(decoded_content), om.end() + 60)
                obf_snippets.append(decoded_content[start:end].strip())
            heuristic_details.append({"rule": "Eval/Obfuscation", "snippets": obf_snippets})
        else:
            analysis_log.append("✅ Heuristic Passed: Eval/Obfuscation")

        all_match_details = match_details + heuristic_details
        analysis_log.append(f"YARA Analysis: {len([m for m in match_details if m.get('namespace') != 'FuzzyDB'])} rules matched")

        # -----------------------------
        # SCORING
        # -----------------------------
        is_fuzzy = any(m.get('namespace') == 'FuzzyDB' for m in match_details)
        total_matches = len(all_match_details)
        base_score = 75 if is_fuzzy else (50 if total_matches > 0 else 0)
        score = min(base_score + (total_matches * 10) + heuristics_score, 100)

        return jsonify({
            "score": score,
            "matches": all_match_details,
            "details": f"Scanned {len(content)} bytes from {source}",
            "analysis_log": analysis_log,
            "content_preview": content_preview,
        })

    except Exception as e: return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5328)