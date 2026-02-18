# Technical Whitepaper: Malware Scanner Architecture

This document serves as a comprehensive technical reference for the malware scanner's implementation. It details the exact mechanisms of data ingestion, memory management, algorithmic detection, and security controls, with direct references to the source code.

---

## 1. System Architecture Overview

The system operates as a stateless, serverless-compatible microservice. It is designed to minimize the attack surface by avoiding persistent storage and executing all analysis in ephemeral memory.

### The Pipeline Logic (\`api/index.py\`)
The entire lifecycle of a request is handled within a single execution context in \`scan()\`:

```python
# api/index.py (Simplified)

@app.route('/api/scan', methods=['POST'])
def scan():
    # 1. Ingestion
    if 'file' in request.files:
        f = request.files['file']
        content = f.read()  # Loaded into RAM
    
    # 2. Analysis
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

1.  **Ingestion**: `Checking Content-Type` (detecting `multipart/form-data` vs `application/x-www-form-urlencoded`).
2.  **Normalization**: Converting all inputs into a unified `bytes` buffer.
3.  **Analysis**: Running deterministic (YARA) and probabilistic (Heuristic) engines.
4.  **Serialization**: returning a JSON response.
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
    resp = requests.get(url, timeout=5, headers=req_headers, verify=False)
    ```

3.  **DOM Parsing & Recursion**:
    - The HTML content is parsed into a DOM tree using `BeautifulSoup`.
    - The system performs a **Depth-1 Traversal**:
        - It identifies all `<script src="...">` nodes.
        - It identifies all `<link rel="stylesheet" href="...">` nodes.
        - It resolves relative paths (e.g., `src="/js/app.js"`) to absolute URLs using `urllib.parse.urljoin`.
    - **Constraint**: To prevent DoS (Denial of Service) via infinite recursion, we cap asset fetching at **10 files per type** and impose a **3-second timeout** per request.
    ```python
    # api/index.py

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(process_asset, t, p): p for t, p in assets_to_scan}
    ```

### B. File Handling (Memory Safety)
-   **Multipart Parsing**: The Flask framework parses the incoming standard HTTP POST stream.
-   **Buffering**: The file is read via `f.read()`. In Python, this loads the entire byte sequence into a continuous block of RAM.
    ```python
    if 'file' in request.files:
        f = request.files['file']
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

### B1. Byte-Code vs. Text
YARA does not "read text." It compares **hexadecimal byte sequences**.
-   **Example**: The rule `Executable_Header` looks for `MZ`.
-   **Internal Logic**: The engine looks for the byte `0x4D` followed immediately by `0x5A` at `offset 0` of the buffer.
-   **Handling Encodings**: If a rule specifies a string "eval", YARA searches for the ASCII bytes `65 76 61 6C`. The `nocase` modifier tells the engine to also accept `45 56 41 4C` (EVAL) and mixed permutations.

### B2. Implementation
We use the `yara-python` binding to execute the compiled rules against the memory buffer.

```python
# api/index.py

# 1. Compile Rules on Startup
rules = yara.compile(filepath=RULES_PATH)

# 2. Match Content
matches = rules.match(data=content)

# 3. Extract Snippets
for m in matches:
    snippets = []
    for string_match in m.strings:
        # extraction logic...
```

### C. Condition Evaluation
YARA rules (in `api/rules/malware.yar`) allow complex boolean logic.
-   **Byte-Code vs. Text**: YARA compares hexadecimal byte sequences (e.g., `MZ` = `0x4D 0x5A`) rather than just "text."
-   **Short-Circuiting**: If a rule condition is `filesize < 500KB` and the file is 600KB, the engine stops immediately.

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

## 4. Heuristic Analysis (Behavioral Logic)

While YARA handles known signatures, we use Python `re` (Regular Expressions) for behavioral anomalies in `api/index.py`.

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

## 5. Scoring Mathematics
The risk score is a deterministic calculation, not an AI guess.

$$ Score = B + (M \times 10) + H $$

-   **Base ($B$)**: 50 if matches > 0, else 0.
-   **Matches ($M$)**: Count of YARA rules matched.
-   **Heuristics ($H$)**: +20 for Redirects, +15 for Obfuscation.

The result is capped at 100.

```python
# api/index.py

base_score = 50 if total_matches > 0 else 0
score = base_score + (total_matches * 10) + heuristics_score
score = min(score, 100)
```

---

## 6. Frontend Visualization Mechanics

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

## 7. Application Layout

The application layout is defined in `src/app/page.tsx`. It orchestrates the transition between the Scanner, Simplified Docs, and this Whitepaper using `framer-motion` for smooth animations.

```typescript
// src/app/page.tsx

export default function Home() {
    const [currentView, setCurrentView] = useState<"scanner" | "simple" | "advanced">("scanner");

    return (
        <main>
            {/* Navigation Menu */}
            <MenuSheet currentView={currentView} onViewChange={setCurrentView} />

            {/* View Switcher with Animations */}
            <AnimatePresence mode="wait">
                {currentView === 'scanner' ? (
                    <Scanner />
                ) : (
                    <CodeDocsViewer 
                        content={currentView === 'simple' ? SIMPLE_DOCS : ADVANCED_DOCS} 
                    />
                )}
            </AnimatePresence>
        </main>
    );
}
```

---

## 8. Security Summary

| Vector | Defense Mechanism | Technical Source |
|:---|:---|:---|
| **Remote Code Execution (RCE)** | Passive Analysis | No `exec()`, `subprocess.call()`, or rendering engines used in `api/index.py`. |
| **SSRF** | IP Filtering | `is_safe_url()` (socket + ipaddress check) in `api/index.py`. |
| **DoS (Recursive Fetching)** | Limits & Timeouts | `timeout=2` and `max_workers=10` limits in `api/index.py`. |
| **Persistence** | RAM-Only | Files are read into memory variables and never saved to disk (`f.read()` vs `f.save()`). |
