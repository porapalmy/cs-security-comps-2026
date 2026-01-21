from flask import Flask, request, jsonify
import yara
import os
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# Compile rules on load. In a lambda, this happens on cold start.
# Path relative to this file: ./rules/malware.yar
RULES_PATH = os.path.join(os.path.dirname(__file__), 'rules', 'malware.yar')

rules = None
if os.path.exists(RULES_PATH):
    try:
        rules = yara.compile(filepath=RULES_PATH)
    except Exception as e:
        print(f"YARA compilation error: {e}")
else:
    print(f"Rule file not found at {RULES_PATH}")

from security import is_safe_url
import urllib3

# Suppress InsecureRequestWarning for scanned sites
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@app.route('/api/scan', methods=['POST'])
def scan():
    global rules
    if not rules:
        # Try finding it again (debugging paths in serverless can be tricky)
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
        
        # Scoring Logic (naive)
        score = 0
        if match_names:
            score = 50 + (len(match_names) * 10)
            score = min(score, 100)
        
        return jsonify({
            "score": score,
            "matches": match_names,
            "details": f"Scanned {len(content)} bytes from {source}"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5328)
