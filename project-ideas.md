# Idea 1: YARA-Based Malware Detection and Analysis

## Description

Instead of generating YARA rules from scratch, this project focuses on analyzing existing, real-world YARA rules to understand how they detect malware. We will reverse engineer malware samples using tools such as Ghidra, analyze their assembly code and runtime behavior, and map these findings directly to the YARA rules that detect them.

Each string, condition, and opcode pattern within a YARA rule will be traced back to specific assembly instructions, API calls, or embedded data in the malware. This creates an educational bridge between static analysis and practical malware detection.

We may slightly modify or extend existing YARA rules to improve clarity, reduce false positives, or adapt them to malware variants, demonstrating how defenders maintain detection signatures over time. The project may also be extended by incorporating machine learning techniques to suggest or refine YARA rules.

The overall goal is to evaluate how effective and explainable YARA rules are when grounded in reverse engineering analysis, while exploring extensible methods for improvement. To make the project more accessible, we also plan to develop user-facing components, such as a web application or a browser extension, to present our analysis and detection results.

## Potential Deliverables

- Selected malware samples and corresponding public YARA rules
- Reverse engineering reports (assembly analysis, control flow, behavior)
- Annotated YARA rules with explanations
- Modified YARA rules with justification for changes
- Detection accuracy and false-positive evaluation comparing baseline and modified YARA rules
- _Optional:_ simple web application or browser extension to present results

## Testing Methodology

- Run malware samples in a sandboxed virtual machine
- Scan samples using the original YARA rules
- Modify rules and re-scan to evaluate changes in detection
- Test rules against benign software to measure false positives
- Compare detection results before and after rule modifications

## Potential Barriers to Success

- Difficulty in modifying YARA rule code to ensure efficiency and reliability
- Choosing appropriate tools to create sandboxed virtual machines (e.g., UTM), given a mix of macOS (Intel and Apple Silicon) and Windows users
- Determining whether to limit the scope to analyzing existing YARA rules if rule modification proves too complex
