# Iterative Bicluster-to-YARA Pipeline Summary (file_bicluster_iterative)

## Dataset
- Samples root: `/home/ubuntu/malware-lab/samples/files_exe`
- Categories: `Ransomware, Stealer, Trojan`

## Iteration Metrics

| Iteration | Sample Coverage | Cluster Coverage | Active Rules | Dead Rules | yaraQA Issues |
|---:|---:|---:|---:|---:|---:|
| 1 | 0.6867 | 0.5714 | 3 | 2 | 0 |
| 2 | 0.6867 | 0.5714 | 3 | 2 | 0 |
| 3 | 0.6867 | 0.5714 | 3 | 2 | 0 |
| 4 | 0.6867 | 0.5714 | 4 | 1 | 0 |
| 5 | 0.6867 | 0.5714 | 4 | 1 | 0 |
| 6 | 0.6867 | 0.5714 | 4 | 1 | 0 |

## Final Output
- Final manifest rules: **5**
- Final rules file: `/home/ubuntu/malware-lab/palmy-scripts/file-pipeline/final-results/final_improved_rules.yar`

## Notes
- Initial rules are seeded from spectral co-cluster feature signatures.
- Each iteration runs evaluation + yaraQA feedback before rule updates.
- Improvement step currently uses deterministic heuristic rewrites.
