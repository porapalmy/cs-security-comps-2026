## Short description of the project

Our project studies how YARA-based malware detection works in practice by combining reverse engineering, rule analysis, and applied detection. We analyze both machine-learning–generated YARA rules and real-world public YARA rules, evaluating how they detect web-delivered malware and phishing kits. By reverse engineering malware samples and mapping YARA rule indicators back to concrete code and artifacts, we aim to make detection results explainable and understandable. As a practical component, we will build a web-based tool that scans submitted files with YARA rules and returns clear explanations of detections, matched indicators, and overall risk.

---

## List of learning goals

By the end of this project, we aim to understand the following concepts and systems that we do not fully understand today:

1) YARA in real-world, web-delivered malware detection  

How YARA rules are applied to non-binary artifacts, including:
- HTML loaders  
- JavaScript droppers  
- ZIP archives containing phishing kits or multi-stage payloads  

What distinguishes effective YARA rules for web-delivered threats from rules written for native Windows executables?  

How directory structure, filenames, embedded assets, and script logic are leveraged in YARA-based phishing kit detection.

2) How ML-based YARA rule generators work internally  

What features ML-driven YARA generators extract from files (e.g., strings, opcodes, metadata, file structure).  

How these features are transformed into concrete YARA rule components (strings, hex patterns, conditions).  

Where machine learning decisions end, and heuristic or rule-based logic begins in these systems.  

The strengths and limitations of ML-assisted rule generation compared to manual rule writing.

3) Reverse engineering as a foundation for explainable detection  

How reverse engineering techniques (static analysis in Ghidra) reveal the semantic meaning behind YARA indicators.  

How individual YARA strings, hex patterns, and conditions map to:
- specific assembly instructions  
- API calls  
- embedded configuration data  
- phishing kit assets or scripts  

Why malware analysis remains essential even in modern, automated detection pipelines.

4) Detection quality, robustness, and generalization  

How well existing YARA rules generalize beyond the exact samples they were written for.  

Which YARA feature types (plain strings, regexes, hex patterns, metadata conditions) contribute most to:
- reliable detection  
- low false-positive rates  
- robustness against minor variants  

How YARA compares to simpler string-matching or heuristic baselines when used as a standalone detection engine.

5) Translating low-level signals into user-understandable risk  

How multiple YARA matches, behavioral heuristics, and file characteristics can be combined into a 0–100 risk score.

---

## List of development goals

Be able to identify numerous different types of malware  

Have a website  

As a stretch/product goal, we will extend the ML YARA generator into a user-facing website that scans URLs and files for malware and returns a complete, explainable report (detections, matched indicators, risk summary, and supporting evidence).

We hope our YARA rules website can have the option to choose which software a person might want to increase the efficiency in different areas of checking for malware.

---

## Testing, benchmarking, and analysis plan

### Correctness testing
- Scan known malware samples with known YARA rules  
- False positive evaluation  
- Scan benign datasets of normal websites, PDFs, etc., and count false positives per rule  

### Benchmarking
- Measure scan time across different file types and file sizes  
- Compare performance between baseline rules and improved ones  

### Website
- How effective the front end is to users  
- Ease of use and how frictionless it feels  

### YARA generator rules
- Compare its rules to standard good rules  
- Measure false positives  
- Evaluate how well it integrates into the website  

---

## Rough schedule of development

### End of Week 3
- Finish setting up VM/container  
- Find existing YARA rules that work with website, PDF, and document detection  
- Set up a working YARA generator  
- Set up Docker on everyone’s computers (everyone needs to download)  
- Find 12–15 malware-based YARA rules covering:
  - website (.js, .html, .py)  
  - exe  
  - zip  
  - pdf  
  - docx  

Example rule sources:
- https://github.com/codewatchorg/Burp-Yara-Rules/blob/master/README.md  
- https://github.com/Yara-Rules/rules/blob/master/malware/APT_APT17.yar  

- Have a good explanation of how the selected YARA rules work  
- Review Palmy’s GitHub demonstrations for using YARA on HTML malware  
- See if ITS would be willing to lend us laptops  

### Week 4
- Find commonly existing HTML/JS (website) malware and PDF malware (researching, not downloading yet)  
- Reverse engineer common malware to understand what code YARA rules should focus on  
- Possibly extend reverse engineering into Week 4 if needed  
- Assign 2 people per malware for deeper understanding  
- Jeremy starts working on the frontend of the website  
- Begin downloading malware into the containerized setup  
- Feed malware samples into existing YARA rules (from literature review and YARA generator)  

Because YARA rules are not written by a centralized group, there are discrepancies in quality. Using the malware samples, we will:
- Evaluate efficiency (false positives, false negatives, etc.)  
- Define what makes a “good” YARA rule  
- Read relevant papers to guide testing methodology  

- Aim to test ~100 malware samples split across group members  
- Analyze how well YARA rules detect malware in Docker containers  
- Continue reverse engineering from Week 3 if necessary  

### Week 5
- Identify best-performing YARA rules (from literature and generators) for each malware type (websites, PDFs, etc.)  
- Analyze these rules closely and attempt improvements  
- Possibly fix or extend rules using additional techniques or tools  
- Optionally switch entirely to auto rule generation if more effective  
- Rewrite selected YARA rules to improve efficiency  
- Use YARA evaluation tools such as:
  - YARA evaluator  
  - yaraQA  

- Learn how to score input websites/PDFs based on rule sets  
- Example: apply ~30 YARA rules to a single website and analyze results  
- Decide how each rule contributes to the final score  
- Implement initial scoring UI on the website  

### Week 6
- Complete a draft version of the website  
- Connect YARA rules to the website backend  
- Decide backend stack (Vercel, MongoDB, Supabase, AWS)  
- Discuss progress with Professor Jeff  
- Fix any loose ends or required changes  

> If errors, unexpected issues, or new features arise, the timeline may be pushed by one week.

### Week 7
- Finish malware detection website  
- Finalize analysis and documentation  

### Week 8
- Present project  

### Week 9
- Recap and reflect  
