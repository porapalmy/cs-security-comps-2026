# How It Works: A Simplified Technical Overview

This guide explains the scanner's security concepts in plain English. It bridges the gap between "technical jargon" and "real-world analogies" to show exactly why this tool is safe to use.

---

## 1. The Core Concept: "Reading" vs. "Running"

The most important thing to understand is the difference between **Executing** a file and **Analyzing** it.

*   **Execution (Dangerous)**: When you double-click a PDF or visit a website, your computer follows the instructions inside. If the instruction says "delete files," your computer deletes files.
*   **Analysis (Safe)**: This scanner uses a technique called **Static Analysis**. It reads the file's data like a distinct language but **never follows the instructions**.

**The Analogy:**
Imagine a malicious file is a **recipe for a poison**.
*   If you "execute" it, you cook the recipe and drink the poison.
*   If you "analyze" it, you simply read the piece of paper. You see the words "arsenic" and "cyanide" and know it's dangerous, but you never actually cook or drink anything. You are safe because you are just **reading**, not **doing**.

---

## 2. Web Scanning: The "Proxy" Method

When you scan a URL (like `http://suspicious-site.com`), your browser doesn't go there. The **Scanner Application** goes there for you.

*   **How it works**: The scanner acts as a **Proxy** (an intermediary). It sends a request to the website, downloads the code (HTML, JavaScript), and inspects it.
*   **Why it protects you**:
    *   **No Execution**: The scanner downloads the code but doesn't "play" it. It won't run the malicious pop-ups or downloaders.
    *   **Anonymity**: The malicious website sees the Scanner's IP address, not yours. If you are hosting this on a cloud server (like Vercel), the attacker sees Amazon/Vercel's IP. If you are on `localhost` (your own machine), the protection relies on the **Non-Execution** principle described above.

---

## 3. Pattern Matching: The YARA Engine

Deep down, all computer files are just patterns of text and numbers. We use a tool called **YARA** to find "fingerprints" of known malware.

**The "Ctrl+F" Analogy:**
Imagine using "Find" (Ctrl+F) in a document.
*   YARA is like "Find" on steroids.
*   Instead of searching for a word like "Hello," it searches for complex patterns like: *"A hidden command that tries to connect to the internet AND is smaller than 50kb AND contains the word 'password'."*

If a file matches these specific fingerprints (which we call **Rules**), we know it's likely malware, even if we've never seen that specific file before.

---

## 4. Privacy: "Volatile Memory" (RAM)

A major security feature is how we handle data. We use **Memory-Only Processing**.

*   **Hard Drive (Long-term)**: Like writing in a notebook. It stays there until you erase it.
*   **RAM (Short-term)**: Like writing on a fogged-up mirror. It vanishes the moment the steam clears.

**How we use it**:
When you upload a file, it is stored *only* in the scanner's **RAM** (Random Access Memory). We analyze it in milliseconds. Once the analysis is done and the report is sent to you, the program "forgets" the data. It is never saved to a database, never written to a hard drive, and completely disappears from existence.

---

## Summary

| Feature | Technical Term | Simplified Explanation |
| :--- | :--- | :--- |
| **Safety** | Static Analysis | We read the "recipe" but never cook the "poison." |
| **Web Tech** | Proxy Request | The scanner visits the site so you don't have to. |
| **Detection** | Pattern Matching (YARA) | We look for "fingerprints" of bad behavior in the code. |
| **Privacy** | Ephemeral RAM Processing | The file exists only for a split second in memory, then vanishes. |
