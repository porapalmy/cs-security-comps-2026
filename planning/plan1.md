# Short Description of the Project

Our project studies how YARA-based malware detection works in practice by combining reverse engineering, rule analysis, and applied detection. We analyze both machine-learning–generated YARA rules and real-world public YARA rules, evaluating how they detect web-delivered malware and phishing kits. By reverse engineering malware samples and mapping YARA rule indicators back to concrete code and artifacts, we aim to make detection results explainable and understandable. As a practical component, we will build a web-based tool that scans submitted files with YARA rules and returns clear explanations of detections, matched indicators, and overall risk.

---

# List of Learning Goals  
*What do you want to end up understanding that you don't understand yet?*

By the end of this project, we aim to understand the following concepts and systems that we do not fully understand today:

## 1) YARA in real-world, web-delivered malware detection
How YARA rules are applied to non-binary artifacts, including:
- HTML loaders  
- JavaScript droppers  
- ZIP archives containing phishing kits or multi-stage payloads  

What distinguishes effective YARA rules for web-delivered threats from rules written for native Windows executables?  
How directory structure, filenames, embedded assets, and script logic are leveraged in YARA-based phishing kit detection.

## 2) How ML-based YARA rule generators work internally
What features ML-driven YARA generators extract from files (e.g., strings, opcodes, metadata, file structure).  
How these features are transformed into concrete YARA rule components (strings, hex patterns, conditions).  
Where machine learning decisions end, and heuristic or rule-based logic begins in these systems.  
The strengths and limitations of ML-assisted rule generation compared to manual rule writing.

## 3) Reverse engineering as a foundation for explainable detection
How reverse engineering techniques (static analysis in Ghidra) reveal the semantic meaning behind YARA indicators.  
How individual YARA strings, hex patterns, and conditions map to:
- specific assembly instructions,  
- API calls,  
- embedded configuration data,  
- phishing kit assets or scripts.  

Why malware analysis remains essential even in modern, automated detection pipelines.

## 4) Detection quality, robustness, and generalization
How well existing YARA rules generalize beyond the exact samples they were written for.  
Which YARA feature types (plain strings, regexes, hex patterns, metadata conditions) contribute most to:
- reliable detection,  
- low false-positive rates,  
- robustness against minor variants.  

How YARA compares to simpler string-matching or heuristic baselines when used as a standalone detection engine.

## 5) Translating low-level signals into user-understandable risk
How multiple YARA matches, behavioral heuristics, and file characteristics can be combined into a 0–100 risk score.

---

# List of Development Goals  
*What features do you want your software to have by the end of the project? You can label some items as “stretch goals”*

- Be able to identify numerous different types of malware  
- Have a Website  
- As a stretch/product goal, we will extend the ML YARA generator into a user-facing website that scans URLs and files for malware and returns a complete, explainable report (detections, matched indicators, risk summary, and supporting evidence).  
- We hope our YARA rules website can have the option to choose which software a person might want to increase the efficiency in different areas of checking for malware.

---

# Discussion of Testing and Benchmarking

## Correctness Testing
- Scan known malware samples with known YARA rules  
- False positive evaluation  
- Scan benign datasets of normal websites, pdfs, etc, and count the false positive per rule  

## Benchmarking
- Measure scan time across different file types and file sizes  
- Compare performance between the baseline rules and improving ones  

## Website
- How effective front end is to users  
- Easy of use and as frictionless as possible  

## YARA Generator rules
- Compare its rules to standard good rules  
- Low false positives  
- How well it integrated into the website  

---

# Rough Schedule of Development

*What steps will you take, and what will be your deadlines? (Keeping in mind parallel work and team allocation)*

## End of Week 3
- Finish setting up VM/container, finding YARA existing rules that work with websites, pdfs, etc., and setting up a working YARA Generator  
- Set up our docker on everyone’s computers. Everyone needs to download.  
- Find 12–15 malware-based YARA rules (website [.js, .html, .py], exe, zips, pdf, docx, etc)  
- References:  
  - https://github.com/codewatchorg/Burp-Yara-Rules/blob/master/README.md  
  - https://github.com/Yara-Rules/rules/blob/master/malware/APT_APT17.yar  
- Have a good explanation of how the YARA rules work for checking above rules  
- Palmy has pushed some demonstrations to github for specifically using yara for HTML malware  
- See if ITS would be willing to lend us laptops?  

## Week 4
- Start with finding commonly existing html/js (website) malwares and pdf malwares (just looking, not downloading yet)  
- Reverse engineer the common malware to see what is the code for YARA rules we should focus on. Not sure how long will take maybe goes into week 4. Maybe have 2 people focusing on one malware just so we have a better understanding  
- Jeremy will start to work on the front end of the website  
- Start downloading malwares into our setup container, feeding a lot of malwares to our yara rules (that we found from the literature reviews and from the YARA generator). Because right now yara rules are not made from a centralized group of people, there can be a lot of discrepancies of what works well or not. So using the malware we found, we can try:
  - find the efficiency (false positives, false negatives, or etc) of the YARA rules (this is how we define which one is essentially a good yara rule). Read some of this paper to understand how we can go about testing.  
- Aim to test around 100 malwares in our dockers split between the group members  
- Analyze how well the yara rules detect the malwares that are run in the dockers  
- Continue reverse engineering of malware from Week 3 if needed  

## Week 5
- After we found the best YARA rules (from literatures and from the Generators) for each malware type (websites or PDFs), we will look at them closely and find ways to improve (if possible usually through making it find the malware on websites), maybe fix the rules itself or extended with different techniques/softwares or entirely switch to auto rule generator  
- After testing the yara rules, rewrite some of the rules to make them more efficient (and aiming to use Yara evaluators such as Yara evaluator, yaraQA)  
- Learn how to score the input website/pdf/etc based on the set of yara rules. Random website, take around 30 YARA rules and the website and see what results are given. How we will score from each rule.  
- Implement some of this scoring front-end onto the website  

## Week 6
- The draft of website should be done  
- Learn how to connect our YARA rules to the website we built (backend, how?) Vercel, MongoDB, Supabase, AWS  
- Discuss with Professor Jeff and fix any loose ends that need to be changed  

> If we get any errors or unexpected issues or new features, the timeline will be pushed by a week.

## Week 7
- Finish our malware detection website, alongside with concluding our projects and writing  

## Week 8
- Present  

## Week 9
- Recap and Reflect  