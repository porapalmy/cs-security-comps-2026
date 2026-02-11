from flask import Flask, request, jsonify
import yara
import os
import re
import socket
import ipaddress
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import urllib3

# Suppress InsecureRequestWarning for scanned sites
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_safe_url(url):
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

# Compile rules on load (cold start in serverless)
RULES_PATH = os.path.join(os.path.dirname(__file__), 'rules', 'malware.yar')

rules = None
if os.path.exists(RULES_PATH):
    try:
        rules = yara.compile(filepath=RULES_PATH)
    except Exception as e:
        print(f"YARA compilation error: {e}")
else:
    print(f"Rule file not found at {RULES_PATH}")

@app.route('/api/scan', methods=['POST'])
def scan():
    global rules
    if not rules:
        return jsonify({"score": 0, "matches": [], "details": "Error: YARA rules not loaded."}), 500

    content = b""
    source = ""

    input_type = request.form.get('type') # 'file' or 'url'

    try:
        if 'file' in request.files:
            f = request.files['file']
            content = f.read()
            source = f.filename
        
        elif 'url' in request.form:
            url = request.form['url']
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Security Check: SSRF Protection
            if not is_safe_url(url):
                 return jsonify({"error": "Security Alert: Scanning internal or private network resources is prohibited."}), 403

            source = url
            # verify=False is necessary for malware/phishing sites that often have bad certs
            resp = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
            content = resp.content
        
        else:
             return jsonify({"error": "No content provided"}), 400

        # Run YARA
        matches = rules.match(data=content)
        match_names = [m.rule for m in matches]
        
        # Python-based Heuristic Analysis (for transparency)
        analysis_log = []
        heuristics_score = 0
        decoded_content = ""
        try:
            decoded_content = content.decode('utf-8', errors='ignore')
        except:
            decoded_content = str(content)

        # 1. Content Preview
        content_preview = decoded_content[:2000] # First 2KB
        analysis_log.append("Extracted content preview (2KB)")

        # 2. Heuristic Checks
        found_heuristics = []
        
        # Check 1: Suspicious Redirects (Regex for accuracy)
        redirect_pattern = re.compile(r'(window\.location\s*=|http-equiv=["\']refresh["\'])', re.IGNORECASE)
        if redirect_pattern.search(decoded_content):
            analysis_log.append("❌ Heuristic Failed: Suspicious Redirects (found potential auto-redirect)")
            heuristics_score += 20
            found_heuristics.append("Suspicious Redirects")
        else:
             analysis_log.append("✅ Heuristic Passed: Suspicious Redirects")

        # Check 2: Obfuscation
        obfuscation_markers = ["eval(", "unescape(", "document.write("]
        found_obfuscation = [m for m in obfuscation_markers if m in decoded_content.lower()]
        if found_obfuscation:
             analysis_log.append(f"❌ Heuristic Failed: Eval/Obfuscation (found: {', '.join(found_obfuscation)})")
             heuristics_score += 15
             found_heuristics.append("Eval/Obfuscation")
        else:
             analysis_log.append("✅ Heuristic Passed: Eval/Obfuscation")

        analysis_log.append(f"YARA Analysis: {len(matches)} rules matched")

        # Scoring Logic (Hybrid)
        score = 0
        base_score = 50 if match_names else 0
        score = base_score + (len(match_names) * 10) + heuristics_score
        score = min(score, 100)
        
        return jsonify({
            "score": score,
            "matches": match_names + found_heuristics,
            "details": f"Scanned {len(content)} bytes from {source}",
            "analysis_log": analysis_log,
            "content_preview": content_preview
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5328)
