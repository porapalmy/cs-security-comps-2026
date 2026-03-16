# Iterative Bicluster-to-YARA Pipeline Summary (web_bicluster_iterative)

## Dataset
- Samples root: `/home/ubuntu/malware-lab/samples/extracted`
- Categories: `ExploitKit, javascript, phishing, php`

## Iteration Metrics

| Iteration | Sample Coverage | Cluster Coverage | Active Rules | Dead Rules | yaraQA Issues |
|---:|---:|---:|---:|---:|---:|
| 1 | 0.1287 | 0.3333 | 3 | 3 | 0 |
| 2 | 0.2543 | 0.5556 | 4 | 2 | 0 |
| 3 | 0.2543 | 0.5556 | 4 | 2 | 0 |
| 4 | 0.2543 | 0.5556 | 5 | 1 | 0 |
| 5 | 0.2727 | 0.6667 | 6 | 0 | 0 |
| 6 | 0.2727 | 0.6667 | 6 | 0 | 0 |

## Final Output
- Final manifest rules: **6**
- Final rules file: `/home/ubuntu/malware-lab/palmy-scripts/web-pipeline/final-results/final_improved_rules.yar`

## Notes
- Initial rules are seeded from spectral co-cluster feature signatures.
- Each iteration runs evaluation + yaraQA feedback before rule updates.
- Improvement step currently uses deterministic heuristic rewrites.
