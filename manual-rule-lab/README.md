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
- `initial-rules-literature/`: A curated collection of YARA rules for web-based and file-based malware, gathered from online research and literature review.
- `Dockerfile`: Configuration for containerized environments.
- `run_file_pipeline.sh`: Script to execute the file-based pipeline.
- `run_web_pipeline.sh`: Script to execute the web-based pipeline.
- `visualize-pipeline.py`: Script for visualizing pipeline results.
- `file-pipeline/`: Contains output for file-based malware analysis.
- `web-pipeline/`: Contains output for web-based malware analysis.

Inside the results of web and file pipelines:

- `initial-rules/`: Initial generated rules and manifest.
- `iterations/`: Per-iteration rules, evaluations, yaraQA results, and change logs.
- `final-results/`: Final improved rules and summaries.
- `bicluster/`: Bicluster grouping artifacts.
- `figures/`: Visualizations and graphs generated during the pipeline.

## Quick Run (Web Dataset)

```bash
cd manual-rule-lab/web-pipeline
source venv/bin/activate

python3 run_pipeline.py \
  --samples-root malware-lab/samples/extracted \
  --categories ExploitKit,javascript,phishing,php \
  --dataset-label web_bicluster_iterative \
  --output-root manual-rule-lab \
  --n-biclusters 8 \
  --max-iterations 6 \
  --target-sample-coverage 0.70 \
  --target-cluster-coverage 0.85 \
  --max-yaraqa-issues 10
```

## Quick Run (File Dataset)

```bash
cd manual-rule-lab/file-pipeline
source venv/bin/activate

python3 run_pipeline.py \
  --samples-root malware-lab/samples/extracted \
  --categories Ransomware,Stealer,Trojan \
  --dataset-label file_bicluster_iterative \
  --output-root manual-rule-lab \
  --n-biclusters 6 \
  --max-iterations 6 \
  --target-sample-coverage 0.75 \
  --target-cluster-coverage 0.90 \
  --max-yaraqa-issues 15
```

## Output

### Initial rule

- `manual-rule-lab/web-pipeline/initial-rules/initial_cluster_rules.yar`
- `manual-rule-lab/web-pipeline/initial-rules/rules_manifest.json`

### Iteration logs

- `manual-rule-lab/web-pipeline/iterations/iter_01/...`
- `manual-rule-lab/web-pipeline/iterations/iter_02/...`
- ...

Each iteration includes:

- `rules/cluster_rules.yar`
- `eval.json`
- `yaraqa_issues.json`
- `yaraqa_summary.json`
- `changes.json` (if not final)

### Final artifacts

- `manual-rule-lab/web-pipeline/final-results/final_improved_rules.yar`
- `manual-rule-lab/web-pipeline/final-results/final_rules_manifest.json`
- `manual-rule-lab/web-pipeline/final-results/final_eval.json`
- `manual-rule-lab/web-pipeline/final-results/final_yaraqa_issues.json`
- `manual-rule-lab/web-pipeline/final-results/pipeline_summary.json`
- `manual-rule-lab/web-pipeline/final-results/pipeline_summary.md`

## Requirements

- Python packages used by sklearn/numpy already available in your environment.
- `yara` CLI must be available in PATH.
- Download `yaraQA` to this folder (`manual-rule-lab`) by cloning the repository:

```bash
git clone https://github.com/Neo23x0/yaraQA.git
```

- The `yaraQA` script is expected at `manual-rule-lab/yaraQA/yaraQA.py`. Ensure the script is executable and properly configured.
