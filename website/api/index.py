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
rule_sources = {}  # rule_name -> raw YARA rule text (for transparency in frontend)

if os.path.exists(RULES_PATH):
    try:
        rules = yara.compile(filepath=RULES_PATH)
        # Parse individual rule blocks from the .yar file
        raw_yar = open(RULES_PATH, 'r').read()
        for block in re.findall(r'(rule\s+\w+\s*\{[^}]*\{[^}]*\}[^}]*\}|rule\s+\w+\s*\{[^}]*\})', raw_yar, re.DOTALL):
            name_match = re.match(r'rule\s+(\w+)', block)
            if name_match:
                rule_sources[name_match.group(1)] = block.strip()
        print(f"Loaded {len(rule_sources)} YARA rule sources: {list(rule_sources.keys())}")
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
            req_headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.get(url, timeout=5, headers=req_headers, verify=False)
            html_content = resp.content

            # Parse HTML and fetch linked JS/CSS
            from urllib.parse import urljoin
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Prepare assets for parallel scanning
            assets_to_scan = []
            
            # 1. Collect Scripts
            for tag in soup.find_all('script', src=True)[:10]:
                assets_to_scan.append(('js', tag['src']))
            
            # 2. Collect CSS
            for tag in soup.find_all('link', rel='stylesheet', href=True)[:10]:
                assets_to_scan.append(('css', tag['href']))
            
            # Helper for parallel execution
            def process_asset(asset_type, asset_path):
                try:
                    full_url = urljoin(url, asset_path)
                    if not is_safe_url(full_url): return None
                    
                    # Strict 2s timeout for assets
                    r = requests.get(full_url, timeout=2, headers=req_headers, verify=False)
                    if r.status_code != 200: return None
                    
                    # Size limit: 500KB per asset to prevent hanging on huge files
                    if len(r.content) > 500 * 1024: return None
                    
                    content_text = r.content.decode('utf-8', errors='ignore')
                    
                    # YARA Scan
                    matches = rules.match(data=r.content)
                    results = []
                    
                    for m in matches:
                        snippets = []
                        for string_match in m.strings:
                            for instance in string_match.instances:
                                offset = instance.offset
                                start = max(0, offset - 60)
                                end = min(len(content_text), offset + len(instance.matched_data) + 60)
                                snip = content_text[start:end].strip()
                                if snip and len(snippets) < 3:
                                    snippets.append(snip)
                        results.append({"rule": m.rule, "snippets": snippets, "yaraRule": rule_sources.get(m.rule)})
                        
                    return {
                        "type": asset_type,
                        "name": asset_path.split('/')[-1] or "asset",
                        "content": content_text[:2000], 
                        "matches": results,
                        "bytes": r.content
                    }
                except Exception:
                    return None

            # Execute parallel fetches
            asset_contents_bytes = []
            match_details = []
            
            # YARA Scan on Main HTML
            decoded_html = html_content.decode('utf-8', errors='ignore')
            for m in rules.match(data=html_content):
                snippets = []
                for string_match in m.strings:
                    for instance in string_match.instances:
                        offset = instance.offset
                        start = max(0, offset - 60)
                        end = min(len(decoded_html), offset + len(instance.matched_data) + 60)
                        snip = decoded_html[start:end].strip()
                        if snip and len(snippets) < 3:
                            snippets.append(snip)
                match_details.append({"rule": m.rule, "snippets": snippets, "yaraRule": rule_sources.get(m.rule)})

            # Content Preview Skeleton
            content_preview = {
                "html": decoded_html[:4000],
                "js": [],
                "css": []
            }

            # Run Threads
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_url = {executor.submit(process_asset, t, p): p for t, p in assets_to_scan}
                for future in concurrent.futures.as_completed(future_to_url):
                    data = future.result()
                    if data:
                        # Append Results
                        if data['matches']:
                            match_details.extend(data['matches'])
                        
                        # Add to Preview
                        if data['type'] == 'js':
                            content_preview['js'].append({"name": data['name'], "content": data['content']})
                        elif data['type'] == 'css':
                            content_preview['css'].append({"name": data['name'], "content": data['content']})
                            
                        # Keep bytes for Heuristics
                        asset_contents_bytes.append(data['bytes'])

            # Combine all content for heuristics
            content = html_content
            for b in asset_contents_bytes:
                content += b"\n" + b
        
        else:
             return jsonify({"error": "No content provided"}), 400

        # For file uploads, run YARA on the single file
        if 'file' in request.files:
            decoded_file = content.decode('utf-8', errors='ignore')
            matches = rules.match(data=content)
            match_details = []
            for m in matches:
                snippets = []
                for string_match in m.strings:
                    for instance in string_match.instances:
                        offset = instance.offset
                        start = max(0, offset - 60)
                        end = min(len(decoded_file), offset + len(instance.matched_data) + 60)
                        snippet = decoded_file[start:end].strip()
                        if snippet and len(snippets) < 3:
                            snippets.append(snippet)
                match_details.append({"rule": m.rule, "snippets": snippets, "yaraRule": rule_sources.get(m.rule)})

        # Heuristic Analysis
        analysis_log = []
        heuristics_score = 0
        decoded_content = ""
        try:
            decoded_content = content.decode('utf-8', errors='ignore')
        except:
            decoded_content = str(content)

        # For file uploads, build a simple string preview
        if 'file' in request.files:
            content_preview = decoded_content[:2000]
        
        analysis_log.append(f"Extracted content ({len(content)} bytes total)")

        heuristic_details = []
        
        # Check 1: Suspicious Redirects — require 3+ occurrences to flag
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

        # Check 2: Obfuscation — require 5+ combined occurrences
        obfuscation_markers = ["eval(", "unescape(", "document.write("]
        obf_count = sum(decoded_content.lower().count(m) for m in obfuscation_markers)
        if obf_count >= 5:
             found_markers = [m for m in obfuscation_markers if m in decoded_content.lower()]
             analysis_log.append(f"❌ Heuristic Failed: Eval/Obfuscation ({obf_count} occurrences of: {', '.join(found_markers)})")
             heuristics_score += 15
             # Find first 3 occurrences for snippets
             obf_snippets = []
             obf_re = re.compile(r'(eval\(|unescape\(|document\.write\()', re.IGNORECASE)
             for om in list(obf_re.finditer(decoded_content))[:3]:
                 start = max(0, om.start() - 60)
                 end = min(len(decoded_content), om.end() + 60)
                 obf_snippets.append(decoded_content[start:end].strip())
             heuristic_details.append({"rule": "Eval/Obfuscation", "snippets": obf_snippets})
        else:
             analysis_log.append("✅ Heuristic Passed: Eval/Obfuscation")

        all_match_details = match_details + heuristic_details
        analysis_log.append(f"YARA Analysis: {len(match_details)} rules matched")

        # Scoring
        total_matches = len(all_match_details)
        base_score = 50 if total_matches > 0 else 0
        score = base_score + (total_matches * 10) + heuristics_score
        score = min(score, 100)
        
        return jsonify({
            "score": score,
            "matches": all_match_details,
            "details": f"Scanned {len(content)} bytes from {source}",
            "analysis_log": analysis_log,
            "content_preview": content_preview
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5328)
