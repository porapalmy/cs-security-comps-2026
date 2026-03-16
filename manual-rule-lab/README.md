# manual-rule-lab

This folder contains a comprehensive pipeline for malware analysis and rule generation. The pipeline follows these steps:

1. Bicluster malware samples by extracted string features.
2. Collect initial YARA rules from bicluster signatures.
3. Evaluate rules against bicluster-defined sample clusters.
4. Run yaraQA on current rules.
5. Iterate rule updates using evaluation and yaraQA feedback.
6. Produce final improved rules and metrics.

## Files and Folders

- `run_pipeline.py`: One-command end-to-end runner.
- `pipeline_lib.py`: Shared pipeline logic.
- `initial-rules/`: Initial generated rules and manifest.
- `initial-rules-literature/`: A curated collection of YARA rules for web-based and file-based malware, gathered from online research and literature review.
- `iterations/`: Per-iteration rules, evaluations, yaraQA results, and change logs.
- `final-results/`: Final improved rules and summaries.
- `bicluster/`: Bicluster grouping artifacts.

## Quick Run (Web Dataset)

```bash
cd /home/ubuntu/malware-lab
source venv_unified/bin/activate

python3 palmy-scripts/run_pipeline.py \
  --samples-root samples/extracted \
  --categories ExploitKit,javascript,phishing,php \
  --dataset-label web_bicluster_iterative \
  --output-root palmy-scripts \
  --n-biclusters 8 \
  --max-iterations 6 \
  --target-sample-coverage 0.70 \
  --target-cluster-coverage 0.85 \
  --max-yaraqa-issues 10
```

## Quick Run (File Dataset)

```bash
cd /home/ubuntu/malware-lab
source venv_unified/bin/activate

python3 palmy-scripts/run_pipeline.py \
  --samples-root samples/files_exe \
  --categories Ransomware,Stealer,Trojan \
  --dataset-label file_bicluster_iterative \
  --output-root palmy-scripts \
  --n-biclusters 6 \
  --max-iterations 6 \
  --target-sample-coverage 0.75 \
  --target-cluster-coverage 0.90 \
  --max-yaraqa-issues 15
```

## Output You Will Get

### Initial rule

- `palmy-scripts/initial-rules/initial_cluster_rules.yar`
- `palmy-scripts/initial-rules/rules_manifest.json`

### Iteration logs

- `palmy-scripts/iterations/iter_01/...`
- `palmy-scripts/iterations/iter_02/...`
- ...

Each iteration includes:

- `rules/cluster_rules.yar`
- `eval.json`
- `yaraqa_issues.json`
- `yaraqa_summary.json`
- `changes.json` (if not final)

### Final artifacts

- `palmy-scripts/final-results/final_improved_rules.yar`
- `palmy-scripts/final-results/final_rules_manifest.json`
- `palmy-scripts/final-results/final_eval.json`
- `palmy-scripts/final-results/final_yaraqa_issues.json`
- `palmy-scripts/final-results/pipeline_summary.json`
- `palmy-scripts/final-results/pipeline_summary.md`

## Requirements

- Python packages used by sklearn/numpy already available in your environment
- `yara` CLI must be available in PATH
- `yaraQA` script expected at `rule-dev/tools/yaraQA/yaraQA.py`

You can override yaraQA script location with:

```bash
--yaraqa-script /absolute/path/to/yaraQA.py
```
