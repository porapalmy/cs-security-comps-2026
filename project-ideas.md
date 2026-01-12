# Idea 1: YARA-Based Malware Detection and Analysis

## Description

Instead of generating YARA rules from scratch, this project focuses on analyzing existing, real-world YARA rules to understand how they detect malware. We will reverse engineer malware (aka just looking at the source code) samples using tools such as Ghidra, analyze their assembly code and runtime behavior, and map these findings directly to the YARA rules that detect them, so we can better understand what YARA identifies in the malware code. Each string, condition, and opcode pattern within a YARA rule will be traced back to specific assembly instructions, API calls, or embedded data in the malware. So we can see the connection between general analysis and practical malware detection.

We may slightly modify or extend existing YARA rules to improve clarity, reduce false positives, or adapt them to malware variants, demonstrating how defenders maintain detection signatures over time. The project may also be extended by incorporating machine learning techniques to suggest or refine YARA rules.

The overall goal is to evaluate how effective and explainable YARA rules are when grounded in reverse engineering analysis, while exploring extensible methods for improvement. To make the project more accessible, we also plan to develop user-facing components, such as a web application or a browser extension, to present our analysis and detection results.

## Potential Deliverables

- Selected malware samples and corresponding public YARA rules
- Reverse engineering reports (assembly analysis, control flow, behavior)
- Annotated YARA rules with explanations
- Modified YARA rules with justification for changes
- Detection accuracy and false-positive evaluation comparing baseline and modified YARA rules
- Simple web application and browser extension to present results

## Testing Methodology

- Run malware samples in a sandboxed virtual machine
- Scan samples using the original YARA rules
- Modify rules and re-scan to evaluate changes in detection
- Test rules against benign software to measure false positives
- Compare detection results before and after rule modifications

## Potential Problems

- How difficult is it to modify YARA rule code ourselves to make it efficient and reliable?
- Which programs should we use to create sandboxed virtual machines (like UTM?), given that our group includes macOS (Intel and Apple Silicon) and Windows users? What would be the easiest and most optimal solution for everyone?
- If modifying the YARA code is too hard, should we just only use and analyze the existing one?

---

# Idea 2: Canaries

## Description

## Potential Deliverables

## Testing Methodology

## Potential Problems
