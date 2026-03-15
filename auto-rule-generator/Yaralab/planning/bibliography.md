# Research Questions and Resources

---

## Q1: How are YARA rules used to detect web-delivered malware and phishing kits, and what makes them effective outside native binaries?

### And, based on types of web-delivered malware families, how are they realistic, analyzable, and appropriate targets for YARA-based detection and scoring?

### Scope and Motivation

This question examines how YARA rules are applied to **web-delivered malware**, including HTML pages, JavaScript files, ZIP archives, and phishing kits, rather than traditional native Windows executables. It also investigates which malware families commonly rely on these delivery mechanisms and are realistic, well-documented, and safe to analyze in a controlled environment.

By grounding our project in concrete, real-world malware families delivered via URLs, we avoid designing detection logic in the abstract and instead align our YARA rules and scoring logic with realistic attacker behavior observed in the wild.

### Key Aspects

- How YARA operates on HTML, JavaScript, ZIP archives, and phishing kits (not just PE files)
- Which YARA rule features (strings, regex, hex patterns, metadata, conditions) matter most for web-delivered threats
- How real-world YARA rulesets detect malicious content fetched from URLs
- Malware families delivered via HTML, JavaScript, redirects, and archives
- Phishing kits vs droppers vs loaders
- What malware is safe, realistic, and well-documented to analyze
- How academic literature studies web-based malware without relying on native executables

### Core Resources

**YARA – The Pattern Matching Swiss Army Knife for Malware Researchers**  
VirusTotal / YARA Project  
https://virustotal.github.io/yara/  
_Description:_ Describes YARA rule syntax (strings, hex patterns, conditions, modules) and how YARA is used in real malware classification pipelines.  
_Relevance:_ Defines how our backend can match against HTML, JavaScript, and downloaded files.

**What Are YARA Rules?** – Picus Security  
https://www.picussecurity.com/resource/glossary/what-is-a-yara-rule  
_Description:_ Practical overview of how YARA rules act as “genetic markers” for malware.  
_Relevance:_ Provides conceptual framing for explaining why YARA works.

**YARA Rules Explained** – Cymulate  
https://cymulate.com/cybersecurity-glossary/yara-rules/  
_Description:_ Clear explanation of rule structure and operational use in threat hunting.  
_Relevance:_ Helps justify how we structure and interpret rules.

**PhishingKit-YARA-Rules** – StalkPhish  
https://stalkphish.com/products/phishingkit-yara-rules/  
_Description:_ Open-source YARA ruleset for detecting phishing kits based on directory structure, filenames, and brand assets inside downloaded ZIP files.  
_Relevance:_ Directly applicable to detecting malicious content fetched from URLs.

**VMRay YARA Rule Updates**  
https://www.vmray.com/february-2025-detection-highlights-a-record-month-of-new-yara-rules/  
_Description:_ Shows how a commercial sandbox deploys large YARA rule sets to detect phishing kits and malware families.  
_Relevance:_ Demonstrates real-world scale and coverage of YARA in web-delivered threats.

**How to Write YARA Rules That Minimize False Positives** – Intezer  
https://intezer.com/blog/yara-rules-minimize-false-positives/  
_Description:_ Examines common sources of false positives and provides guidance on improving rule generalization.  
_Relevance:_ Supports experiments evaluating rule robustness and variant detection.

**MalwareBazaar – Web-Delivered Malware Samples**  
https://bazaar.abuse.ch/  
_Description:_ Public repository of malware samples delivered via URLs, including JavaScript droppers, HTML loaders, and archive-based payloads.  
_Relevance:_ Provides realistic samples for testing and analysis.

**Analyzing and Defending Against Web-Based Malware** – ACM  
https://dl.acm.org/doi/abs/10.1145/2501654.2501663

**Investigation and Analysis of Malware on Websites** – IEEE  
https://ieeexplore.ieee.org/abstract/document/5623567

**WebPatrol: Automated Collection and Replay of Web-Based Malware Scenarios** – ACM  
https://dl.acm.org/doi/abs/10.1145/1966913.1966938

**The Ghost in the Browser: Analysis of Web-Based Malware** – USENIX  
https://www.usenix.org/legacy/events/hotbots07/tech/full_papers/provos/provos.pdf

_Relevance:_ These works collectively demonstrate that web-based malware can be systematically collected, analyzed, and defended against by examining malicious HTML, JavaScript, and browser behaviors, without relying solely on native executable analysis.

**YARA Rules – Glossary and Overview** – Corelight  
https://corelight.com/resources/glossary/yara-rules#cite  
_Description:_ Explains the role of YARA rules in modern malware analysis and threat detection.  
_Applicability:_ Useful for background and motivation, and for situating YARA within contemporary security workflows.

---

## Q2: How effective is YARA as a standalone detection engine compared to simpler string-matching or heuristic approaches?

### Scope

This question evaluates YARA as a detection mechanism on its own, without relying on machine learning models or sandbox-only behavioral analysis.

### Key Aspects

- YARA vs naïve string matching
- Rule structure, tags, and conditions as structured heuristics
- Strengths and limitations of YARA-based detection

### Core Resources

**Using YARA Tags to Build a Heuristic Scanner** – Dani  
https://vixra.org/pdf/2003.0214v1.pdf  
_Description:_ Explores how YARA rules and tags can be used to construct a heuristic malware scanner.  
_Applicability:_ Provides conceptual grounding for evaluating YARA against simpler string-based baselines.

**A Comparative Study of Malware Detection Techniques Using YARA, Cryptographic Hashing, and Fuzzy Hashing** – arXiv  
https://arxiv.org/pdf/2111.13910

---

## Q3: How have YARA-based malware scanners been built, integrated, and evaluated in practice?

### Scope

This question focuses on real-world systems that integrate YARA into malware detection pipelines and how these systems are evaluated.

### Key Aspects

- Existing system architectures using YARA
- Evaluation methods (accuracy, false positives, benign testing)
- Logging, alerting, and production integration

### Core Resources

**Simple Malware Scanner Using YARA** – IJDIM  
https://ijdim.com/journal/index.php/ijdim/article/download/259/234  
_Description:_ Web-based YARA scanner evaluated on malware and benign samples with reported accuracy and false-positive rates.  
_Relevance:_ Provides a defensible evaluation template for our own system.

**Wazuh – Detecting Malware Using YARA Integration**  
https://documentation.wazuh.com/current/proof-of-concept-guide/detect-malware-yara-integration.html  
_Description:_ Demonstrates YARA integration into a production security pipeline with logging and alerts.  
_Relevance:_ Inspires how our backend should track and report YARA matches.
