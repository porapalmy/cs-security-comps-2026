# gap-analysis-lab

This folder contains the order of steps for fuzzy hashing on YARA rules:

1. Run baseline YARA audit against Bi-clustering and yarGen rulesets
2. Identify and log malware samples that bypassed all current YARA detection
3. Generate Context-Triggered Piecewise Hashes (fuzzy hashes) for all undetected samples
4. Index malware signatures into a SQLite database for secondary website lookups
5. Perform all-vs-all structural similarity cross-comparison of the undetected dataset
6. Produce a final "Smoking Gun" report identifying renamed malware mutations and evasion attempts

## Files

- `baseline_check.py`: Audits the library against existing rule groups to find detection gaps
- `fuzzy_analysis.py`: Pipeline for ppdeep hashing, SQLite indexing, and similarity research
- `after_fuzzy.py`: Filters research data to find renamed files with high structural similarity
- `rachel-tests/`: Working directory for all CSV reports, logs, and detection databases

## Gap Analysis Pipeline

```bash
cd /home/ubuntu/malware-lab/rachel-tests

# 1. Baseline: Find what YARA is missing
python3 baseline_check.py

# 2. Analysis: Cluster missed files by structural similarity
python3 fuzzy_analysis.py

# 3. Report: Identify renamed malware mutations (Smoking Guns)
python3 after_fuzzy.py


## Output You Will Get

### Baseline Audit Results

- `rachel-tests/baseline_deep_comparison.csv`: Full Hit/Miss status for every sample across rulesets
- `rachel-tests/target_files_for_fuzzy.txt`: List of paths for files that bypassed YARA detection

### Fuzzy Research Artifacts

- `rachel-tests/malware_fuzzy.db`: SQLite database containing file paths and fuzzy hashes
- `rachel-tests/fuzzy_matches.csv`: Raw similarity scores for all pairs of undetected samples (50%+ similarity)

### Final Mutation Report

- `rachel-tests/smoking_guns_summary.txt`: Detailed report of different filenames sharing similar content (70%+ similarity)

## Requirements

- Python packages: `yara-python`, `ppdeep`, `py7zr`, `pandas`, `tqdm`, `sqlite3`
- Access to the malware sample library at `/home/ubuntu/malware-lab/samples/extracted`
- Pre-compiled YARA rules in `/home/ubuntu/malware-lab/yara-rules/web-yara` and `/home/ubuntu/yara-lab/rule_library/generated`