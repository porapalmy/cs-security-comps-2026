from flask import Flask, request, jsonify
from flask_cors import CORS  # Added for website connection
import yara
import os
import re
import socket
import ipaddress
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
import urllib3
import sqlite3 # Added for Fuzzy
import ppdeep  # Added for Fuzzy
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

        if str(ip_obj) == "169.254.169.254":
            return False

        return True
    except Exception:
        return False


app = Flask(__name__)
CORS(app) # Allow your website to talk to this API

# -----------------------------
# Paths (Back to your original style)
# -----------------------------
RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
DB_PATH = os.path.join(BASE_DIR, "malware_fuzzy.db") 

# Compiled YARA ruleset
rules = None
rule_sources = {}

# -----------------------------
# Fuzzy Search Logic
# -----------------------------
def fuzzy_search_fallback(file_content):
    if not os.path.exists(DB_PATH):
        return []
    try:
        uploaded_hash = ppdeep.hash(file_content)
        chunk_size = int(uploaded_hash.split(':')[0])
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM signatures WHERE chunk_size IN (?, ?, ?)", 
                       (chunk_size, chunk_size // 2, chunk_size * 2))
        candidates = cursor.fetchall()
        fuzzy_matches = []
        for row in candidates:
            score = ppdeep.compare(uploaded_hash, row['fuzzy_hash'])
            if score >= 50:
                fuzzy_matches.append({
                    "rule": f"Fuzzy Match: {score}% Similarity",
                    "namespace": "FuzzyDB",
                    "ruleKey": f"fuzzy:{row['id']}",
                    "ruleFile": row['file_name'],
                    "snippets": [f"Known variant found in DB"],
                    "yaraRule": None 
                })
        conn.close()
        return fuzzy_matches
    except Exception:
        return []

# -----------------------------
# YARA Rule Loading
# -----------------------------
def _extract_rule_blocks(yara_text: str):
    pattern = re.compile(r"(?ms)\brule\s+([A-Za-z_]\w*)\b.*?\{.*?\n\}", re.DOTALL)
    for m in pattern.finditer(yara_text):
        yield m.group(1), m.group(0).strip()

def load_yara_rules_from_dir(rules_dir: str):
    sources = {}
    valid_filepaths = {}
    bad_files = []
    parsed_blocks = 0
    print(f"[YARA] Loading rules from: {rules_dir}", flush=True)
    if not os.path.isdir(rules_dir):
        print(f"[YARA] Rules directory not found: {rules_dir}", flush=True)
        return None, sources, {"total_files": 0, "valid_files": 0, "skipped_files": 0, "skipped": [], "parsed_rule_blocks": 0}

    rule_files = []
    for root, _, files in os.walk(rules_dir):
        for fn in files:
            if fn.lower().endswith((".yar", ".yara")):
                rule_files.append(os.path.join(root, fn))
    rule_files.sort()
    
    for path in rule_files:
        rel = os.path.relpath(path, rules_dir)
        ns = re.sub(r"[^A-Za-z0-9_]+", "_", os.path.splitext(rel)[0])
        try:
            yara.compile(filepath=path)
            valid_filepaths[ns] = path
            raw = open(path, "r", encoding="utf-8", errors="ignore").read()
            for rule_name, rule_block in _extract_rule_blocks(raw):
                sources[f"{ns}:{rule_name}"] = {"text": rule_block, "path": rel, "namespace": ns}
                parsed_blocks += 1
        except Exception as e:
            bad_files.append({"path": rel, "error": str(e)})

    try:
        compiled = yara.compile(filepaths=valid_filepaths)
        print("[YARA] Aggregated ruleset compiled successfully.", flush=True)
        return compiled, sources, {}
    except Exception as e:
        print(f"[YARA] Error: {e}", flush=True)
        return None, sources, {}

rules, rule_sources, yara_load_stats = load_yara_rules_from_dir(RULES_DIR)

# -----------------------------
# Scan Engine (original logic + Fuzzy)
# -----------------------------
def format_match(m, snippets):
    ns = getattr(m, "namespace", None)
    rule_key = f"{ns}:{m.rule}" if ns else m.rule
    src = rule_sources.get(rule_key)
    return {"rule": m.rule, "namespace": ns, "ruleKey": rule_key, "ruleFile": src.get("path") if src else None, "snippets": snippets, "yaraRule": src.get("text") if src else None}

def build_snippets(decoded_text: str, m, max_snippets: int = 3, context: int = 60):
    snippets = []
    try:
        for string_match in getattr(m, "strings", []):
            for instance in getattr(string_match, "instances", []):
                offset = getattr(instance, "offset", None)
                if offset is not None:
                    snip = decoded_text[max(0, offset-context):min(len(decoded_text), offset+60)].strip()
                    if snip and len(snippets) < max_snippets: snippets.append(snip)
    except: pass
    return snippets

@app.route("/api/scan", methods=["POST"])
def scan():
    if not rules: return jsonify({"error": "Rules not loaded"}), 500
    
    content = b""
    match_details = []
    analysis_log = []

    if "file" in request.files:
        f = request.files["file"]
        content = f.read()
        decoded_file = content.decode("utf-8", errors="ignore")
        matches = rules.match(data=content)
        for m in matches:
            match_details.append(format_match(m, build_snippets(decoded_file, m)))
        
        # Fuzzy fallback
        if not match_details:
            fuzzy = fuzzy_search_fallback(content)
            if fuzzy:
                match_details.extend(fuzzy)
                analysis_log.append("🔍 YARA Missed. Fuzzy DB found structural matches.")
        
        content_preview = decoded_file[:2000]

    elif "url" in request.form:
        # ... (Keep your original URL scanning block from before here)
        pass

    # -----------------------------
    # Original Heuristics
    # -----------------------------
    # (Check 1: Redirects, Check 2: Obfuscation - Keep all your original lines here)
    
    total_matches = len(match_details)
    score = min((50 if total_matches > 0 else 0) + (total_matches * 10), 100)

    return jsonify({
        "score": score,
        "matches": match_details,
        "analysis_log": analysis_log,
        "content_preview": "..."
    })

if __name__ == "__main__":
    app.run(debug=True, port=5328)