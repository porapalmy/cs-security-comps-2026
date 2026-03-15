#!/usr/bin/env bash
set -euo pipefail

cd /home/ubuntu/malware-lab
source venv_unified/bin/activate

python3 palmy-scripts/run_pipeline.py \
  --samples-root samples/files_exe \
  --categories Ransomware,Stealer,Trojan \
  --dataset-label file_bicluster_iterative \
  --output-root palmy-scripts/file-pipeline \
  --n-biclusters 6 \
  --max-features 600 \
  --max-iterations 6 \
  --target-sample-coverage 0.70 \
  --target-cluster-coverage 0.85 \
  --max-yaraqa-issues 10

echo "File pipeline finished."
echo "Outputs: /home/ubuntu/malware-lab/palmy-scripts/file-pipeline"