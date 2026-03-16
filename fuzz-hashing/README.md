# gap-analysis-lab

## Reasoning for doing Fuzzy Hashing
- A limitation of YARA rules is that it can only detect common malware in existence that we have considered in our samples right now. But for extreme malware cases that weren’t in our samples or if attackers improve their malware code overtime, our collection may not be able to detect it, so we needed to consider a gap that could be used to detect likely malicious files, even if our YARA rules don’t recognise future unknown malware. 

- YARA rules ignore non malicious/inert files, such as images, gifs or non malicious html and phps files.  Even though some files in malware packages may not be malicious, they are purposely put there by the attacker. So even though attackers may improve and change their malware to make it undetectable by YARA rules, they usually don’t change their inert files. We decided to do an analysis of these non-malicious files that were not detectable by Yara rules by using a fuzzy hashing method.


This folder contains the order of steps for fuzzy hashing on our YARA rules:

1. Run baseline YARA check against Bi-clustering and yarGen rulesets
2. Identify and log malware samples that bypassed all current YARA detection
3. Generate Context-Triggered Piecewise Hashes (fuzzy hashes) for all undetected samples
4. Index malware signatures into a SQLite database for potential secondary website lookups
5. Perform all-vs-all structural similarity cross-comparison of the undetected dataset
6. Produce a final "Summary of Similarities" report identifying variations of non-malicious files.

## Requirements

- Python packages: `yara-python`, `ppdeep`, `py7zr`, `pandas`, `tqdm`, `sqlite3`
- Access to the malware sample library at `/home/ubuntu/malware-lab/samples/extracted`
- Pre-compiled YARA rules in `/home/ubuntu/malware-lab/yara-rules/web-yara` and `/home/ubuntu/yara-lab/rule_library/generated`

## Files

- `baseline_check.py`: Checks the library against existing rule groups to find detection gaps
- `fuzzy_analysis.py`: Pipeline for ppdeep hashing, SQLite indexing, and similarity research
- `after_fuzzy.py`: Filters research data to find renamed files with high similarity
- `malware_fuzzy.db`: Hashing Database based on original run through comparing made YARA rules against samples

## Gap Analysis Pipeline

```bash
cd /home/ubuntu/malware-lab/rachel-tests
source venv_unified/bin/activate

# 1. Baseline: Find what files YARA is missing
python3 baseline_check.py

# 2. Analysis: Based on target files missed, run the fuzzy hashing on them and then compare
python3 fuzzy_analysis.py

# 3. Report: Give a summary of identified different files that have the similar hashes 
python3 after_fuzzy.py


## Output You Will Get

### Baseline Audit Results

- `rachel-tests/baseline_deep_comparison.csv`: Full Hit/Miss status for every sample across rulesets
- `rachel-tests/target_files_for_fuzzy.txt`: List of paths for files that bypassed YARA detection

### Fuzzy Research Artifacts

- `rachel-tests/malware_fuzzy.db`: SQLite database containing file paths and fuzzy hashes
- `rachel-tests/fuzzy_matches.csv`: Raw similarity scores for all pairs of undetected samples (50%+ similarity)

### Final Mutation Report

- `rachel-tests/summary_of_similarities.txt`: Detailed report of different filenames sharing similar content depending on hash (70%+ similarity)
