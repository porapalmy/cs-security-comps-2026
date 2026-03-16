# ScanMal — YARA-based Malware Detection and Analysis

[![Project Status: Active](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

ScanMal is a compact research and tooling repository for YARA-based malware detection, rule generation, and web scanning. It contains pipeline tooling for collecting malware samples, generating and refining YARA rules, evaluating rule quality, performing fuzzy-hash blind-spot analysis, and deploying rules into a web scanner.

Authors: Rachel Azan, Jeremy G, Palmy Klangsathorn, Daniel Lumbu

---

**Quick links**

- Website (Next.js + Flask): [website/README.md](website/README.md)
- Malware lab & samples guidance: [malware-lab/README.md](malware-lab/README.md)
- Manual rule pipeline: [manual-rule-lab/README.md](manual-rule-lab/README.md)
- Auto rule generator & scanner: [auto-rule-generator/Yaralab/README.md](auto-rule-generator/Yaralab/README.md)
- Fuzzy-hashing analysis: [fuzz-hashing/README.md](fuzz-hashing/README.md)
- Python deps (pinned): [requirements.txt](requirements.txt)

---

## Overview

This repository demonstrates an end-to-end approach for understanding and improving YARA-based detection. The main components are:

- Manual analysis of malware assembly listings (manual review) to map behavior into signatures
- Automatic rule generation from sample corpora
- Iterative refinement and evaluation of candidate rules
- Fuzzy-hash analysis to find blind spots and variants
- Deployment of validated rules into a web scanner for live testing

All components are organized into separate folders so they can be run independently or combined into reproducible pipelines.

---

## Full Pipeline Overview

```
Malware Collection (malware-lab)
                │
        ┌───────┴───────┐
        │               │
 manual-rule-lab   auto-rule-generator
 (clustering +      (automatic rule
  rule improvement)      generation)
        │               │
        └───────┬───────┘
                │
    ┌───────────┴───────────┐
    │    Collection of      │
    │   Improved rules      │
    └───────────┬───────────┘
                │
   Blind Spot Analysis (fuzz-hashing)
                │
      Web Scanner (website)
```

This diagram maps to the modules described below. The goal is to move from raw samples → candidate rules → evaluated rules → robust rules deployed for scanning.

---

## Repository layout

```
cs-security-comps-2026
│
├── malware-lab            # sample collection & extraction
├── manual-rule-lab        # clustering + rule improvement
├── auto-rule-generator    # automatic rule generation (yarGen etc)
├── fuzz-hashing           # fuzzy-hash blind-spot analysis
├── website                # Next.js frontend + Flask API scanner
├── requirements.txt       # pinned Python deps
└── README.md              # this file
```

Each module contains a README with module-specific setup and usage; follow those docs for detailed commands.

---

## Modules (short)

- `malware-lab`: Collects and prepares malware datasets (download, extract, organize). These datasets power the rule-generator and evaluation pipelines.
- `manual-rule-lab`: Implements an iterative pipeline: cluster samples, generate human-readable rule seeds, evaluate with yaraQA, and refine rules.
- `auto-rule-generator`: Uses automated tools (e.g., yarGen) to produce baseline YARA rules from sample corpora; results feed into evaluation and refinement.
- `fuzz-hashing`: Uses fuzzy hashing to locate similar variants and identify blind spots where rules miss modified malware.
- `website`: A demo web scanner (Next.js frontend + Flask API) that accepts file or URL submissions and returns detection scores and explanations.

---

## Quickstart

1. Clone the repository and change directory:

```bash
git clone <repo-url>
cd cs-security-comps-2026
```

2. Create a virtual environment (recommended name: `scanmal-venv`):

```bash
python3 -m venv scanmal-venv
```

3. Install pinned Python dependencies:

```bash
# Activate the environment using your preferred method, then:
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
# or use the project helper which accepts a venv name:
./scripts/install_deps.sh scanmal-venv
```

4. Install common system libraries (if building wheels or compiling native extensions):

Debian / Ubuntu (example):

```bash
sudo apt-get update
sudo apt-get install -y build-essential python3-dev libyara-dev libmagic-dev \
        zlib1g-dev libbz2-dev liblzma-dev gfortran
```

macOS (Homebrew):

```bash
xcode-select --install
brew install yara pkg-config p7zip openblas
```

Notes: `yara-python` may require system YARA headers (`libyara-dev` / `brew install yara`). SciPy/NumPy should install as wheels; if pip attempts to compile them install BLAS/LAPACK dev libs first.

5. Quick verification:

```bash
# Run this after installing dependencies (activate venv if used)
python - <<'PY'
import importlib,sys
pkgs=['flask','numpy','pandas','sklearn','yara','requests']
missing=[p for p in pkgs if importlib.util.find_spec(p) is None]
print('missing:', missing)
if missing:
    sys.exit(1)
PY
```

---

## Algorithms & Results

The root README emphasizes research methods and produced artifacts; module run instructions (including how to start the website) live inside each module's README.

Core algorithms & techniques

- Clustering / biclustering: group samples by extracted string and artifact features to create compact clusters suitable for rule seeding.
- Rule generation: extract candidate strings and artifacts (automated tools such as yarGen are used), prioritize discriminative features, and produce YARA rule candidates based on string/opcode/API patterns.
- Iterative Refinement: evaluate generated rules, inspect mismatches and false positives, and refine rules with a human-in-the-loop to improve precision and recall.
- Rule evaluation: compute metrics (using yaraQA and custom scripts) such as coverage, false positive rate, cluster coverage, and rule-quality warnings.
- Fuzzy-hash blind-spot analysis: In case YARA rules can't detect anything, use fuzzy-hash techniques (e.g., `ppdeep`/ssdeep) to find near-duplicates and variants based on non malicious files from the malware, then create targeted tests and hashes.

Outputs & where to find them

- `manual-rule-lab/`: seeds, iteration logs, evaluation metrics, and final rules (e.g., `initial-rules/`, `iterations/`, `final-results/`, `bicluster/`).
- `auto-rule-generator/`: automatically generated rule artifacts, extraction logs, and generated YARA sets.
- `fuzz-hashing/`: fuzzy-hash tables and blind-spot reports.
- `website/`: (optional) used for live testing and demonstration; see `website/README.md` for deployment and run instructions.

Common evaluation metrics

- Coverage: fraction of samples matched by a rule in a corpus.
- Precision / false positive rate: measured against benign datasets.
- yaraQA: stylistic and quality checks that surface risky or noisy rules.

For reproduction commands, exact output locations, and module-specific examples, please consult the README in each module.

---

## Running pieces of the pipeline

- Prepare and extract samples: follow `malware-lab/README.md`.
- Generate baseline rules (automatic): see `auto-rule-generator/Yaralab/scan_all_samples.sh` and `auto-rule-generator/Yaralab/scanner/scan.sh`.
- Run the iterative manual pipeline: `python manual-rule-lab/run_pipeline.py ...` (see that module's README for args).
- Perform fuzzy-hash analysis in `fuzz-hashing/`.

For website/backend run instructions see `website/README.md`.

---

## Safety and repository hygiene

- Never commit malware samples or sensitive artifacts. Keep `samples/` and `samples/extracted/` out of git.
- Consider adding `samples/` to your global or repo `.gitignore` if you keep datasets locally.
- Perform all analysis in isolated VMs or containers. Do not run malware on your host.

If you want, I can add `samples/` to `.gitignore` for you.

---

## Testing & evaluation

- Use yaraQA and the evaluation scripts in `manual-rule-lab` to compute rule quality metrics.
- Run detection/false-positive tests by scanning benign software and measuring coverage.

---

## Project goals & deliverables

- Understand how YARA rules detect malware and why
- Produce improved, evaluated YARA rules
- Identify blind spots using fuzzy hashing
- Demonstrate deployment via a web scanner

Deliverables include datasets, rule artifacts, evaluation metrics, and the web-based scanner.
