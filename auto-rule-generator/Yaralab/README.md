# yarGen Integration & Modifications

## Overview

`yarGen` is a **YARA rule generator** used to automatically create detection rules from malware samples. Instead of writing YARA rules manually, `yarGen` analyzes suspicious files and extracts distinctive patterns such as:

* strings
* opcodes
* binary patterns
* file metadata

It then generates candidate **YARA rules** that can be used for malware detection.

In this project, we integrated and modified `yarGen` to support our **malware detection pipeline and rule database**, which powers our scanning system.

---

# What YARA Is

YARA is a **pattern-matching engine used in cybersecurity** to identify malware or suspicious files.

A YARA rule defines:

* patterns to search for
* conditions for when those patterns indicate malware

Example rule structure:

```yara
rule Suspicious_File
{
    meta:
        description = "Detects suspicious script patterns"

    strings:
        $s1 = "powershell"
        $s2 = "cmd.exe"
        $s3 = "eval("

    condition:
        2 of them
}
```

The scanner loads these rules and checks whether files **match the defined patterns**.

---

# What yarGen Does

`yarGen` automates rule creation by analyzing malware samples and identifying **unique indicators**.

Its process:

1. Read malware samples
2. Extract strings and opcode sequences
3. Compare extracted strings against a **goodware database**
4. Remove strings common in benign software
5. Generate candidate YARA rules from the remaining patterns

This produces rules that are **more specific to the malware family**.

---

# How yarGen Works Internally

When `yarGen` runs, the following pipeline occurs:

```
Malware Samples
      │
      ▼
File Analysis
(strings / opcodes extraction)
      │
      ▼
Filtering Stage
(remove common goodware strings)
      │
      ▼
Scoring and Ranking
(select best indicators)
      │
      ▼
Rule Generation
(create YARA rule)
```

Important internal data structures include:

* **file_info dictionary**

Contains metadata about each analyzed sample.

Example structure:

```python
file_info = {
    "strings": [...],
    "opcodes": [...],
    "size": 10234,
    "hash": "...",
    "filetype": "pe"
}
```

This structure is passed through the pipeline until rule generation.

---

# How To Run yarGen

## Basic Command

```bash
python yarGen.py -m <malware_folder> -o <output_rule>
```

Example:

```bash
python yarGen.py -m samples/AsyncRAT -o rules/asyncrat_auto.yar
```

This will:

* analyze malware samples in the folder
* generate YARA rules
* save them to the specified output file

---

## Docker Execution (Used in This Project)

In our malware lab environment we run `yarGen` inside Docker.

Example command:

```bash
docker compose run --rm yargen python yarGen.py \
  -m /opt/mal/AsyncRAT \
  -o /opt/out/AsyncRAT/asyncrat_auto.yar \
  -a "Comps Team Malware Lab"
```

Advantages of using Docker:

* consistent environment
* dependencies already installed
* reproducible results

---

# Code Modifications and Improvements

During this project we modified several parts of `yarGen` to better support our malware research workflow.

---

# 1. Improved String Filtering

### Problem

The default `yarGen` filtering still produced many **generic strings**, such as:

```
http
version
user-agent
config
```

These strings frequently appear in benign software and can cause **false positives**.

### Our Fix

We improved the **string filtering stage** to remove additional generic patterns before rule generation.

This included filtering:

* common web framework markers
* frequently occurring scripting terms
* generic configuration strings

### Result

Generated rules now contain **more distinctive indicators**, improving detection quality.

---

# 2. Improved Rule Conditions

### Problem

Original rules sometimes required too many strings to match, which made detection unreliable.

Example:

```
5 of them
```

If malware variants removed even one string, the rule would fail.

### Our Improvement

We modified rule conditions to use **more flexible matching** such as:

```
2 of ($x*)
```

or

```
any of ($s*)
```

### Result

Rules became:

* more resilient to malware variation
* more reliable in real-world detection.

---

# 3. Organized Output Structure

### Problem

Generated rules were originally stored in a single location, making it difficult to manage large rule sets.

### Our Improvement

We organized rules by **malware family**.

Example structure:

```
rule_library/
    AsyncRAT/
        asyncrat_auto.yar
    AgentTesla/
        agenttesla_auto.yar
```

### Result

Improved:

* rule management
* rule testing
* family-based detection.

---

# 4. Integrated Rule Generation Into Our Pipeline

We integrated `yarGen` into our **malware analysis pipeline**.

Pipeline architecture:

```
Malware Samples
      │
      ▼
yarGen Rule Generator
      │
      ▼
Rule Review & Cleaning
      │
      ▼
Rule Library Database
      │
      ▼
YARA Scanner
      │
      ▼
Detection Results
```

This allows our system to:

* generate new rules from malware
* store them in a rule database
* scan files or websites using those rules.

---

# Goodware Database

A critical component of `yarGen` is the **goodware database**.

This database contains strings extracted from **benign software**.

When `yarGen` generates rules, it removes strings that also appear in goodware.

This reduces **false positives**.

Example goodware strings:

```
printf
malloc
config
http
```

These would normally appear in many programs and therefore are not useful malware indicators.

---

# Limitations

While `yarGen` is powerful, it has some limitations:

* generated rules still require **manual review**
* obfuscated malware may hide useful strings
* compressed files (.zip, .7z) must be extracted before analysis
* polymorphic malware may require multiple rules.

Because of this, `yarGen` is best used as a **rule generation starting point**, not a fully automated solution.

---

# Example Generated Rule

Example output from `yarGen`:

```yara
rule AsyncRAT_Auto_Generated
{
    meta:
        description = "AsyncRAT detection rule"
        author = "Comps Team Malware Lab"

    strings:
        $s1 = "AsyncClient"
        $s2 = "pastebin.com"
        $s3 = "Process Injection"

    condition:
        2 of them
}
```

---

# Summary

`yarGen` plays a critical role in our malware research project by:

* automatically generating YARA rules
* accelerating malware family analysis
* supporting the rule library used by our scanner

Our modifications improved:

* rule accuracy
* filtering quality
* rule organization
* integration with our scanning pipeline.


