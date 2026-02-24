# Technical Whitepaper: Malware Scanner Architecture

This document serves as a comprehensive technical reference for the malware scanner's implementation. It details the exact mechanisms of data ingestion, memory management, algorithmic detection, and security controls, with direct references to the source code.

---

## 1. System Architecture Overview

The system operates as a stateless, serverless-compatible microservice. It is designed to minimize the attack surface by avoiding persistent storage and executing all analysis in ephemeral memory.

### The Pipeline Logic (`api/index.py`)
The entire lifecycle of a request is handled within a single execution context in `scan()`:

```python
# api/index.py (Simplified)

@app.route('/api/scan', methods=['POST'])
def scan():
    # 1. Ingestion
    if 'file' in request.files:
        f = request.files['file']
        content = f.read()  # File upload → raw bytes loaded into RAM

    elif 'url' in request.form:
        # URL scan → raw HTML bytes
        resp = requests.get(url, ...)
        html_content = resp.content

    # 2. Analysis (YARA + Parallel Asset Scanning)
    matches = rules.match(data=content)

    # 3. Heuristics
    heuristics_score = 0
    # ... checks for redirects and obfuscation ...

    # 4. Serialization
    return jsonify({
        "score": score,
        "matches": all_match_details
    })
```

1.  **Ingestion**: Detecting input type (`multipart/form-data` for files vs `application/x-www-form-urlencoded` for URLs).
2.  **Normalization**: Converting all inputs into a unified `bytes` buffer.
3.  **Analysis**: Running deterministic (YARA) and probabilistic (Heuristic) engines.
4.  **Serialization**: Returning a JSON response.
5.  **Teardown**: The Python garbage collector releases all memory handles.

---

## 2. Ingestion & Pre-Processing

### A. URL Proxying Mechanics
When a user submits a URL, the backend acts as a **transparent forward proxy**.

1.  **DNS Resolution & SSRF Protection**:
    - The system calls `socket.gethostbyname(hostname)`.
    - **Security Control**: The resolved IP is compared against `ipaddress.ip_address(ip).is_private`.
    - **Why**: This prevents **SSRF** (Server-Side Request Forgery). Without this, an attacker could request `http://localhost:5000/admin` or `http://169.254.169.254` (AWS Metadata) to steal server secrets.

    ```python
    # api/index.py

    def is_safe_url(url):
        """SSRF protection: block private/loopback/metadata IPs."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)

            # Block valid private ranges (192.168.x.x, 10.x.x.x, etc.)
            if ip_obj.is_private or ip_obj.is_loopback:
                return False

            # Block AWS Metadata service
            if str(ip_obj) == "169.254.169.254":
                return False
            return True
        except Exception:
            return False
    ```

2.  **HTTP Handshake**:
    - We use `requests.get()` with `verify=False`.
    - **Technical Detail**: We intentionally disable SSL Certificate Verification. Malware sites often use self-signed or expired certificates. A standard browser would block these, but our scanner *must* inspect them.
    ```python
    # api/index.py
    # URL scan → raw HTML bytes
    resp = requests.get(url, timeout=5, headers=req_headers, verify=False)
    html_content = resp.content
    ```

3.  **DOM Parsing & Asset Discovery**:
    - The HTML content is parsed into a DOM tree using `BeautifulSoup`.
    - The system performs a **Depth-1 Traversal**:
        - It identifies all `<script src="...">` nodes (up to 10).
        - It identifies all `<link rel="stylesheet" href="...">` nodes (up to 10).
        - It resolves relative paths (e.g., `src="/js/app.js"`) to absolute URLs using `urllib.parse.urljoin`.
    ```python
    # api/index.py

    # 1. Collect Scripts
    for tag in soup.find_all('script', src=True)[:10]:
        assets_to_scan.append(('js', tag['src']))

    # 2. Collect CSS
    for tag in soup.find_all('link', rel='stylesheet', href=True)[:10]:
        assets_to_scan.append(('css', tag['href']))
    ```

4.  **Parallel Asset Fetching & Scanning**:
    - Each discovered asset is fetched and YARA-scanned **in parallel** using a `ThreadPoolExecutor` with up to 10 concurrent workers.
    - **Per-Asset Safety Controls**:
        - **SSRF Check**: Each asset URL is validated through `is_safe_url()` before fetching.
        - **Timeout**: Strict 2-second timeout per asset to prevent hanging on unresponsive servers.
        - **Size Limit**: 500KB maximum per asset to prevent memory exhaustion from oversized files.
    - Each worker independently runs `rules.match(data=r.content)` on its asset, extracting match snippets in context (±60 characters around each match).

    ```python
    # api/index.py

    def process_asset(asset_type, asset_path):
        full_url = urljoin(url, asset_path)
        if not is_safe_url(full_url): return None

        # Strict 2s timeout for assets
        r = requests.get(full_url, timeout=2, headers=req_headers, verify=False)
        if r.status_code != 200: return None

        # Size limit: 500KB per asset
        if len(r.content) > 500 * 1024: return None

        # YARA Scan on individual asset
        matches = rules.match(data=r.content)
        # ... extract snippets ...
        return { "type": asset_type, "matches": results, "bytes": r.content }

    # Execute parallel fetches
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(process_asset, t, p): p for t, p in assets_to_scan}
        for future in concurrent.futures.as_completed(future_to_url):
            data = future.result()
            if data:
                match_details.extend(data['matches'])
                asset_contents_bytes.append(data['bytes'])
    ```

    - **Why Parallel?**: A page may reference 15+ external JS/CSS files. Sequential fetching at 2s timeout each could take 30+ seconds. Parallel execution reduces worst-case to ~2-3 seconds total.
    - **Post-Scan Merge**: After all threads complete, all fetched bytes are concatenated with the main HTML for the heuristic analysis phase:
    ```python
    content = html_content
    for b in asset_contents_bytes:
        content += b"\n" + b
    ```

### B. File Handling (Memory Safety)
-   **Multipart Parsing**: The Flask framework parses the incoming standard HTTP POST stream.
-   **Buffering**: The file is read via `f.read()`. In Python, this loads the entire byte sequence into a continuous block of RAM.
    ```python
    if 'file' in request.files:
        f = request.files['file']
        # File upload → raw bytes
        content = f.read()
        # No f.save() is ever called.
    ```
-   **Security Implication**: We do *not* use `f.save()`. This functionality is intentionally omitted to ensure no file handle is ever opened on the host filesystem, nullifying file-system-based exploits (like Zip Slips or symlink attacks).

---

## 3. The Detection Engine: YARA Internals

The core detection utilizes **YARA**, a pattern-matching tool designed for malware research. To understand "how it matches," we must look at the specific algorithms.

### A. The Aho-Corasick Algorithm
When we say YARA "matches strings," it is not looping through the file 50 times for 50 rules.
-   **State Machine**: YARA compiles all strings from all rules into a single **Aho-Corasick automaton**.
-   **Single Pass**: This allows the engine to scan the file in a **single linear pass** (O(n) complexity, where n is file size).
-   **Why this matters**: It means scanning for 100 viruses takes roughly the same time as scanning for 1 virus.

### B. How String Matching Actually Works

A common misconception is that YARA "converts strings to hex" before comparing. **It does not.** YARA operates directly on the raw byte stream and compares patterns byte-by-byte. Here is how each string type works:

#### Plain-text Strings
```yara
$s1 = "<script>" nocase
```
YARA searches the raw bytes for the exact ASCII sequence `3C 73 63 72 69 70 74 3E` (the hex representation of `<script>`). The `nocase` modifier tells the engine to also accept uppercase variants like `3C 53 43 52 49 50 54 3E` (`<SCRIPT>`) and any mixed-case permutation. **No conversion happens** — the file's bytes are compared directly.

#### ASCII + Wide Strings
```yara
$a = "RyukReadMe.txt" ascii wide nocase
```
The `ascii` modifier matches the normal single-byte encoding: `52 79 75 6B 52 65 61 64 4D 65 2E 74 78 74`.
The `wide` modifier matches the UTF-16 little-endian encoding, where each character is followed by a null byte: `52 00 79 00 75 00 6B 00 ...`. This is critical for detecting malware targeting Windows systems, which internally use UTF-16 for string storage in executables.

#### Byte-Level Conditions
```yara
condition:
    uint16(0) == 0x5A4D
```
This reads the first 2 bytes of the file and checks if they equal `4D 5A` (the ASCII for `MZ`). This is the **PE (Portable Executable) magic header** — every `.exe` and `.dll` file starts with these bytes. This condition ensures the rule only fires on genuine Windows executables, not on web pages or text files.

#### Regex Patterns
```yara
$loc1 = /window\.location(\.href)?\s*=\s*/ nocase
```
YARA compiles the regex and runs it against the byte stream. This matches patterns like `window.location =`, `window.location.href=`, etc., regardless of whitespace variations.

#### Hex Blob Detection
```yara
$hexblob = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){30,}/
```
This regex looks for long sequences of hex escape sequences **already written in the source code** (e.g., `\x90\x90\x90...` in a JavaScript file). It is detecting obfuscation patterns, not converting the file to hex.

### C. Implementation
We use the `yara-python` binding to execute the compiled rules against the memory buffer.

```python
# api/index.py

# 1. Compile Rules on Startup
rules = yara.compile(filepath=RULES_PATH)

# 2. Match Content (raw bytes fed directly to the engine)
matches = rules.match(data=content)

# 3. Extract Snippets with Context
for m in matches:
    snippets = []
    for string_match in m.strings:
        for instance in string_match.instances:
            offset = instance.offset
            start = max(0, offset - 60)
            end = min(len(decoded_content), offset + len(instance.matched_data) + 60)
            snippet = decoded_content[start:end].strip()
```

### D. Condition Evaluation
YARA rules (in `api/rules/malware.yar`) allow complex boolean logic.
-   **Short-Circuiting**: If a rule condition is `filesize < 500KB` and the file is 600KB, the engine stops immediately.
-   **Counting**: `2 of them` means at least 2 of the defined strings must match.
-   **Negation**: `not (2 of ($bundler*))` excludes false positives from normal JavaScript bundlers.

```yara
rule Suspicious_Script {
    strings:
        $a = "eval"
        $b = "document.write"
    condition:
        $a and $b
}
```

---

## 4. YARA Rule Catalog

Our rule set (`api/rules/malware.yar`) is divided into two categories based on what they scan.

### A. Web-Focused Rules (Fire on URL Scans)
These rules analyze HTML, JavaScript, and CSS content fetched from websites. They use `filesize` constraints but **do not** require the PE header, so they match web content.

| Rule | Severity | What It Detects |
|:---|:---|:---|
| `Suspicious_Script` | Medium | Pages with 3+ of: `<script>`, `eval(`, `document.write`, `base64` |
| `Executable_Header` | — | The `MZ` magic byte at offset 0 (PE file served via web) |
| `Phishing_Keywords` | — | Social engineering phrases: "verify your account", "update payment", "urgent" |
| `Auto_Redirect` | High | 2+ redirect mechanisms: `window.location =`, `meta refresh`, etc. |
| `Hidden_Iframe` | High | Zero-dimension `<iframe>` elements used for drive-by downloads |
| `WEB_Redirect_Primitives_Medium` | Medium | 3+ JS redirect primitives or excessive `window.open()` calls |
| `WEB_MetaRefresh_Redirect_Medium` | Medium | HTML `<meta http-equiv="refresh">` with a URL redirect |
| `WEB_Forced_Download_High` | High | JS patterns that trigger downloads: Blob URLs, `a[download]`, `msSaveBlob` |
| `WEB_Permission_Abuse_Notifications_Push_High` | High | Notification permission requests combined with push subscription |
| `WEB_JS_Obfuscation_Stack_Medium` | Medium | Layered obfuscation: `eval`/`new Function` + `atob`/`fromCharCode` + long encoded blobs, excluding normal bundlers |

### B. PE/Executable Family Rules (Fire on File Uploads Only)
These rules target specific malware families. They **all** require `uint16(0) == 0x5A4D` (the PE header), meaning they will **never trigger on URL scans** — only on uploaded `.exe`, `.dll`, or other PE files.

| Rule | Family | Type | Key Signatures |
|:---|:---|:---|:---|
| `Emotet_Family` | Emotet | Banking Trojan | `Global\EMOTET` mutex, specific IE7 User-Agent string |
| `Ryuk_Family` | Ryuk | Ransomware | `RyukReadMe.txt` ransom note, `.RYK` extension, "Wake up!" string |
| `LockBit_Family` | LockBit | Ransomware | `LockBit` identifier, `Restore-My-Files.txt`, `.lockbit` extension |
| `WannaCry_Family` | WannaCry | Ransomware | `WannaDecryptor` dropper, `mssecsvc.exe`, `tasksche.exe` service names |
| `TrickBot_Family` | TrickBot | Banking Trojan | `TrickLoader` module, `client_id`/`group_tag` C2 config fields |
| `QakBot_Family` | QakBot | Banking Trojan | `CoreDll.dll` loader, `botnet` identifier |
| `AgentTesla_Family` | AgentTesla | Spyware | Specific User-Agent, SMTP exfiltration strings |
| `RedLine_Family` | RedLine | Infostealer | Credential file targets: `passwords.txt`, `wallet.dat` |
| `DarkComet_Family` | DarkComet | RAT | `DC_MUTEX`, `DCRAT` identifiers |
| `CobaltStrike_Beacon` | Cobalt Strike | Post-Exploitation | `ReflectiveLoader` DLL injection, `Beacon` C2 framework strings |

**Why the `uint16(0) == 0x5A4D` guard matters**: Without it, a webpage containing the text "LockBit" in a news article would be falsely flagged as ransomware. The PE header check ensures these rules only match actual Windows executables that contain these family-specific strings embedded in their binary.

---

## 5. Heuristic Analysis (Behavioral Logic)

While YARA handles known signatures, we use Python `re` (Regular Expressions) for behavioral anomalies in `api/index.py`. The heuristic engine runs on the **combined** byte buffer (HTML + all fetched JS/CSS assets).

### Redirect Chain Detection
**The Logic**: Phishing sites often bounce users through multiple URLs to hide the final destination.
-   **Regex**: `(window\.location\s*=|http-equiv=["']refresh["'])`
-   **Threshold**: If count `≥ 3`, it implies the page is trying to uncontrollably navigate the user.

```python
# api/index.py

# Regex matches window.location assignments or meta-refresh tags
redirect_pattern = re.compile(r'(window\.location\s*=|http-equiv=["\']refresh["\'])', re.IGNORECASE)
redirect_matches = list(redirect_pattern.finditer(decoded_content))

if len(redirect_matches) >= 3:
    heuristics_score += 20
    analysis_log.append(f"❌ Heuristic Failed: Suspicious Redirects")
```

### Obfuscation Entropy
**The Logic**: Malware authors use "packers" to hide code. This results in high-entropy blocks of random-looking characters.
-   **Signals**: High density of `eval()`, `unescape()`, and `document.write()`.
-   **Trigger**: If count `≥ 5`, the code is statistically likely to be obfuscated malicious script.

```python
# api/index.py

obfuscation_markers = ["eval(", "unescape(", "document.write("]
obf_count = sum(decoded_content.lower().count(m) for m in obfuscation_markers)

if obf_count >= 5:
     heuristics_score += 15
     analysis_log.append(f"❌ Heuristic Failed: Eval/Obfuscation")
```

---

## 6. Scoring Mathematics
The risk score is a deterministic calculation, not an AI guess.

$$ Score = B + (M \times 10) + H $$

-   **Base ($B$)**: 50 if matches > 0, else 0.
-   **Matches ($M$)**: Count of YARA rules matched (including per-asset matches from the parallel scan).
-   **Heuristics ($H$)**: +20 for Redirects, +15 for Obfuscation.

The result is capped at 100.

```python
# api/index.py

base_score = 50 if total_matches > 0 else 0
score = base_score + (total_matches * 10) + heuristics_score
score = min(score, 100)
```

---

## 7. Frontend Visualization Mechanics

Usage of `src/components/Scanner.tsx`. This component manages the UI state and drives the "simulation" of scanning activity.

### State Management
We use React hooks to manage the file object and the scan results. `useState` holds the `File` object in browser memory.

```typescript
// src/components/Scanner.tsx

const [activeTab, setActiveTab] = useState<"file" | "url">("file");
const [file, setFile] = useState<File | null>(null);
const [result, setResult] = useState<ScanResult | null>(null);
const [logs, setLogs] = useState<string[]>([]);
```

### Polling Simulation (Optimistic UI)
Since the backend is extremely fast (milliseconds), we simulate a progress log to give visual feedback. This is a **UI/UX pattern** known as "Optimistic UI," keeping the user engaged during the latency of the server request.

```typescript
// src/components/Scanner.tsx

const simulateLogs = (type: "file" | "url") => {
    const fileLogs = [
        "▸ Initializing scan engine...",
        "▸ Streaming file...",
        "▸ Analyze file entropy...",
        "▸ Loading YARA ruleset [malware.yar]",
        // ...
    ];

    logIntervalRef.current = setInterval(() => {
        // Adds one log line every 500ms
        setLogs((prev) => [...prev, selectedLogs[index]]);
    }, 500);
};
```

### API Communication
The file is not sent as JSON. It is sent as `multipart/form-data`, the standard binary transport for HTTP.

```typescript
// src/components/Scanner.tsx

const handleScan = async () => {
    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch("/api/scan", {
        method: "POST",
        body: formData,
    });
    // ...
};
```

---

## 8. Rule Transparency

The backend parses the raw `.yar` file on startup and stores each rule's source text in a dictionary. When a rule matches, its full YARA source is included in the API response, allowing the frontend to display the exact rule that triggered the detection.

```python
# api/index.py

rule_sources = {}  # rule_name -> raw YARA rule text

raw_yar = open(RULES_PATH, 'r').read()
for block in re.findall(r'(rule\s+\w+\s*\{...})', raw_yar, re.DOTALL):
    name_match = re.match(r'rule\s+(\w+)', block)
    if name_match:
        rule_sources[name_match.group(1)] = block.strip()

# In scan results:
match_details.append({
    "rule": m.rule,
    "snippets": snippets,
    "yaraRule": rule_sources.get(m.rule)  # Full rule source for transparency
})
```

This means **adding a new YARA rule is as simple as editing `malware.yar`** — the backend automatically picks it up on restart, parses its source, and includes it in any future match responses.

---

## 9. Security Summary

| Vector | Defense Mechanism | Technical Source |
|:---|:---|:---|
| **Remote Code Execution (RCE)** | Passive Analysis | No `exec()`, `subprocess.call()`, or rendering engines used in `api/index.py`. |
| **SSRF** | IP Filtering + Per-Asset Validation | `is_safe_url()` called on main URL **and** every discovered asset URL. |
| **DoS (Recursive Fetching)** | Limits & Timeouts | Max 10 assets per type, `timeout=2` per asset, 500KB size cap, `max_workers=10`. |
| **DoS (Resource Exhaustion)** | Size Limits | 500KB per asset, 500KB `filesize` constraint in most YARA rules. |
| **Persistence** | RAM-Only | Files are read into memory variables and never saved to disk (`f.read()` vs `f.save()`). |
| **False Positives (PE Rules on Web)** | `uint16(0) == 0x5A4D` Guard | Malware family rules require the PE header, preventing news articles about "LockBit" from triggering alerts. |
| **False Positives (Bundled JS)** | Bundler Exclusion | `WEB_JS_Obfuscation_Stack_Medium` excludes files containing `__webpack_require__` or `__esModule`. |
