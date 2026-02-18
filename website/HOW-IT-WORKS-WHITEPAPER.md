# Technical Whitepaper: Malware Scanner Architecture

This document serves as a comprehensive technical reference for the malware scanner's implementation. It details the exact mechanisms of data ingestion, memory management, algorithmic detection, and security controls.

---

## 1. System Architecture Overview

The system operates as a stateless, serverless-compatible microservice. It is designed to minimize the attack surface by avoiding persistent storage and executing all analysis in ephemeral memory.

### The Pipeline Logic (`api/index.py`)
The entire lifecycle of a request is handled within a single execution context:

1.  **Ingestion**: `Checking Content-Type` (detecting `multipart/form-data` vs `application/x-www-form-urlencoded`).
2.  **Normalization**: Converting all inputs into a unified `bytes` buffer.
3.  **Analysis**: Running deterministic (YARA) and probabilistic (Heuristic) engines.
4.  **Serialization**: returning a JSON response.
5.  **Teardown**: The Python garbage collector releases all memory handles.

---

## 2. Ingestion & Pre-Processing

### A. URL Proxying Mechanics
When a user submits a URL, the backend acts as a **transparent forward proxy**.

1.  **DNS Resolution**:
    - The system calls `socket.gethostbyname(hostname)`.
    - **Security Control**: The resolved IP is compared against `ipaddress.ip_address(ip).is_private`.
    - **Why**: This prevents **SSRF** (Server-Side Request Forgery). Without this, an attacker could request `http://localhost:5000/admin` or `http://169.254.169.254` (AWS Metadata) to steal server secrets.

2.  **HTTP Handshake**:
    - We use `requests.get()` with `verify=False`.
    - **Technical Detail**: We intentionally disable SSL Certificate Verification. Malware sites often use self-signed or expired certificates. A standard browser would block these, but our scanner *must* inspect them.

3.  **DOM Parsing & Recursion**:
    - The HTML content is parsed into a DOM tree using `BeautifulSoup` (lxml parser).
    - The system performs a **Depth-1 Traversal**:
        - It identifies all `<script src="...">` nodes.
        - It identifies all `<link rel="stylesheet" href="...">` nodes.
        - It resolves relative paths (e.g., `src="/js/app.js"`) to absolute URLs using `urllib.parse.urljoin`.
    - **Constraint**: To prevent DoS (Denial of Service) via infinite recursion, we cap asset fetching at **10 files per type** and impose a **3-second timeout** per request.

### B. File Handling (Memory Safety)
-   **Multipart Parsing**: The Flask framework parses the incoming standard HTTP POST stream.
-   **Buffering**: The file is read via `f.read()`. In Python, this loads the entire byte sequence into a continuous block of RAM.
-   **Security Implication**: We do *not* use `f.save()`. This functionality is intentionally omitted to ensure no file handle is ever opened on the host filesystem, nullifying file-system-based exploits (like Zip Slips or symlink attacks).

---

## 3. The Detection Engine: YARA Internals

The core detection utilizes **YARA**, a pattern-matching tool designed for malware research. To understand "how it matches," we must look at the specific algorithms.

### A. The Aho-Corasick Algorithm
When we say YARA "matches strings," it is not looping through the file 50 times for 50 rules.
-   **State Machine**: YARA compiles all strings from all rules into a single **Aho-Corasick automaton**.
-   **Single Pass**: This allows the engine to scan the file in a **single linear pass** (O(n) complexity, where n is file size).
-   **Why this matters**: It means scanning for 100 viruses takes roughly the same time as scanning for 1 virus.

### B. Byte-Code vs. Text
YARA does not "read text." It compares **hexadecimal byte sequences**.
-   **Example**: The rule `Executable_Header` looks for `MZ`.
-   **Internal Logic**: The engine looks for the byte `0x4D` followed immediately by `0x5A` at `offset 0` of the buffer.
-   **Handling Encodings**: If a rule specifies a string "eval", YARA searches for the ASCII bytes `65 76 61 6C`. The `nocase` modifier tells the engine to also accept `45 56 41 4C` (EVAL) and mixed permutations.

### C. Condition Evaluation
A match isn't just finding a string. YARA evaluates a boolean expression tree.
-   **Logic**: `filesize < 500KB and ($s1 or $s2)`
-   **Short-Circuiting**: If the file is 600KB, the engine stops immediately (false condition). It never proceeds to the expensive string search. This optimization is crucial for performance.

---

## 4. Heuristic Analysis (Behavioral Logic)

While YARA handles known signatures, we use Python `re` (Regular Expressions) for behavioral anomalies.

### Redirect Chain Detection
**The Logic**: Phishing sites often bounce users through multiple URLs to hide the final destination.
-   **Regex**: `(window\.location\s*=|http-equiv=["']refresh["'])`
-   **Threshold**: The code counts the number of non-overlapping matches.
-   **Trigger**: If count `≥ 3`, it implies the page is trying to uncontrollably navigate the user.

### Obfuscation Entropy
**The Logic**: Malware authors use "packers" to hide code. This results in high-entropy blocks of random-looking characters.
-   **Signals**: High density of `eval()`, `unescape()`, and `document.write()`.
-   **Regex**: `(eval\(|unescape\(|document\.write\()`
-   **Trigger**: If count `≥ 5`, the code is statistically likely to be obfuscated malicious script rather than a modern web app (which typically uses clean frameworks like React/Vue).

---

## 5. Scoring Mathematics

The risk score is a deterministic calculation, not an AI guess.

$$ Score = B + (M \times 10) + H $$

Where:
-   $B$ (Base) = 50 (if at least one match exists, else 0).
-   $M$ (Matches) = The count of unique YARA rules triggered.
-   $H$ (Heuristics) = +20 for Redirects, +15 for Obfuscation.

*Example*:
A file matches `Suspicious_Script` ($M=1$) and triggers the `Redirect` heuristic ($H=20$).
$Score = 50 + (1 \times 10) + 20 = 80$ (High Risk).

---

## 6. Frontend Visualization Mechanics

Usage of `src/components/Scanner.tsx`:

1.  **State Management**: React `useState` holds the `File` object in browser memory.
2.  **FormData serialization**: The file is not sent as JSON. It is sent as `multipart/form-data`, the standard binary transport for HTTP.
3.  **Polling Simulation**: The `simulateLogs` function uses `setInterval` to output pre-defined strings every 500ms. This is a **UI/UX pattern** known as "Optimistic UI," keeping the user engaged during the latency of the server request.

---

## 7. Security Summary

| Vector | Defense Mechanism | Technical Source |
|:---|:---|:---|
| **Remote Code Execution (RCE)** | Passive Analysis | No `exec()`, `subprocess.call()`, or rendering engines used. |
| **SSRF** | IP Filtering | `socket.gethostbyname` + `ipaddress.is_private` check. |
| **DoS (Recursive Fetching)** | Limits & Timeouts | `requests.get(timeout=3)` and hard-capped list loops. |
| **Persistence (Malware Storage)** | RAM-Only | No database write checks; `content` variable scope is function-local. |
