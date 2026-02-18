# Deep Dive: Architecture, Security & Internals

This document provides a comprehensive technical breakdown of the malware scanner's architecture, specifically focusing on security implications, data handling, and the internal mechanics of the YARA detection engine.

---

## 🔒 Security & Privacy: Is it Safe?

A common concern with online scanners is safety: *"If I upload a virus, will I get hacked? Will the server get infected?"*

### 1. Passive Scanning (No Execution)
The most critical security feature of this scanner is that it is **passive**.
- **How it works**: The scanner treats every input (PDF, EXE, DOCX) as a raw stream of bytes (0s and 1s). It **never executes**, runs, or renders the file.
- **Why you are safe**: Malware requires execution to function. A malicious PDF needs a vulnerable PDF reader to trigger its payload. Since our backend only reads the text/binary patterns without rendering the page, the exploit code remains inert harmless text.
- **The Sandbox**: The scanning process runs in a short-lived, isolated serverless environment that is destroyed immediately after the request finishes.

### 2. Data Ephemerality (RAM Only)
Users often ask: *"How is my file saved? Is it stored in a database?"*
- **In-Memory Processing**: When you upload a file, it is read directly into **Random Access Memory (RAM)** via the `request.files['file'].read()` method.
- **No Disk Storage**: The file is **never written to the hard drive** (`HDD/SSD`). It never touches a database or a file system bucket (like S3).
- **No Cookies/Persistence**: The file extraction is stateless. We do not use cookies, local storage, or sessions to track files.
- **Instant Deletion**: As soon as the `scan()` function returns the JSON result (usually within 1-2 seconds), the memory is freed. The file ceases to exist on our end.

### 3. Anonymity & Scraper Mechanics
*"Will my IP get tracked when I scrape a URL?"*
- **The Proxy Effect**: When you scan a URL (e.g., `http://malicious-site.com`), **you** do not visit the site—our **server** does.
- **What the Target Sees**: The malicious website's server logs will see a request coming from our secure cloud infrastructure IP (Vercel/AWS), **not your personal home IP address**.
- **Your Protection**: This protects you from "drive-by downloads" or IP logging by the malicious actor. You remain safely behind our infrastructure.

---

## 🔍 YARA Engine: The Internals

The core of the detection logic is [YARA](https://virustotal.github.io/yara/), a battle-tested tool used by malware researchers to identify malware families.

### 1. How YARA Works (Byte-Level Matching)
YARA is often described as "grep on steroids." It doesn't just look for text; it scans for:
- **Hexadecimal Patterns**: Specific sequences of bytes that define executable headers or shellcode.
- **Strings**: Text patterns (ASCII, Unicode, Case-insensitive).
- **Regex**: Complex regular expressions.

**Example Logic**:
Instead of "running" a program to see if it seeks admin privileges, YARA looks at the binary code for the *instruction sequence* that requests those privileges.

### 2. What We Scan For
Our integration (`api/rules/malware.yar`) compiles specific signatures:

| Signature Type | Technical Detail | Why It's Flagged |
|:---|:---|:---|
| **Magic Bytes** | `MZ` (0x4D 0x5A) at offset 0 | Validates if a file is a Windows Executable (EXE/DLL), checking the file header regardless of extension. |
| **Obfuscated JS** | `eval(String.fromCharCode(...))` | Detects code that tries to hide itself by decoding payload at runtime. |
| **Shellcode** | Long strings of hex `\x90\x90...` | Detects "NOP sleds" or buffer overflow payloads often embedded in PDFs. |
| **Embeds** | `<iframe width=0>` | Detects invisible iframes used to load background malware. |

### 3. Testing & Comparison
- **Compilation**: On server start, `yara.compile()` runs. If the syntax is invalid, the server fails safely (logs error, continues without rules).
- **Matching**: The `rules.match(data=content)` method scans the entire byte buffer. It returns a list of *every* rule that satisfied its condition.
- **Conditionals**: Rules are smart. A rule might say: *"Flag if 'suspicious_string' appears MORE than 3 times AND file size is < 500KB."*

---

## 🛠 The Pipeline: Step-by-Step

Here is the exact lifecycle of a scan request (`api/index.py`):

### Phase 1: Ingestion
1. **Input**: User sends POST request to `/api/scan`.
2. **Type Check**: Backend determines if it's a `file` (multipart/form-data) or `url` (string).
3. **SSRF Guard**: If URL, the `is_safe_url()` function resolves the hostname.
   - *Security Check*: usage of `socket.gethostbyname` checks if the IP is private (e.g., `127.0.0.1` or `192.168.1.1`). If so, it **aborts**. This prevents attackers from using our scanner to map our internal network.

### Phase 2: Extraction & fetching
- **For Files**: Bytes are read into variable `content`.
- **For URLs**:
  1. `requests.get()` pulls the HTML.
  2. `BeautifulSoup` parses the DOM.
  3. **Recursive Fetching**: The scanner finds all `<script src="...">` and `<link href="...">` tags.
  4. It downloads those external assets (up to 10 of each) to analyze the *actual code* running on the page, not just the HTML skeleton.

### Phase 3: Analysis
1. **YARA Scan**: The byte buffer is passed to the C-based YARA engine.
   - *Output*: List of Rule Names (e.g., `WEB_Forced_Download_High`) and the specific `strings` that matched.
2. **Heuristic Scan**: Python logic runs regex checks for patterns too complex for simple YARA strings:
   - *Count Redirects*: `window.location` > 3 times?
   - *Count Obfuscation*: `eval()` + `unescape()` > 5 times?

### Phase 4: Scoring
The final score is calculated:
`Score = 50 (Base) + (10 × Match_Count) + Heuristic_Bonus`
- Caps at **100**.
- Example: 1 match (`Suspicious_Script`) + 1 Heuristic (`Redirect`) = `50 + 10 + 20 = 80` (High Risk).

### Phase 5: Response
A JSON object is returned to the frontend.
- **Transparency**: We send back the *actual snippets* of code that triggered the alarm.
- **Cleanup**: The `content` variable goes out of scope, and Python's garbage collector frees the RAM. Nothing remains.

---

## 📊 Visual Summary

```mermaid
graph TD
    User[User] -->|Uploads PDF/URL| API[Flask API (RAM Only)]
    API -->|1. Validation| SSRF[SSRF Protection\n(No internal IPs)]
    SSRF -->|2. Extraction| Bytes[Raw Byte Stream]
    Bytes -->|3. Feed| YARA[YARA Engine]
    Bytes -->|4. Feed| Heur[Python Heuristics]
    YARA -->|Matches| Score[Scoring Algo]
    Heur -->|Matches| Score
    Score -->|JSON Result| Frontend[React UI]
    API -.->|Garbage Collection| Void((Deleted))
```
