#!/usr/bin/env bash
set -euo pipefail

cd /home/ubuntu/malware-lab
source venv_unified/bin/activate

python3 palmy-scripts/run_pipeline.py \
  --samples-root samples/extracted \
  --categories ExploitKit,javascript,phishing,php \
  --dataset-label web_bicluster_iterative \
  --output-root palmy-scripts/web-pipeline \
  --n-biclusters 8 \
  --max-features 700 \
  --max-iterations 6 \
  --target-sample-coverage 0.70 \
  --target-cluster-coverage 0.85 \
  --max-yaraqa-issues 10

echo "Web pipeline finished."
echo "Outputs: /home/ubuntu/malware-lab/palmy-scripts/web-pipeline"
