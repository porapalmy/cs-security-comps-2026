#!/usr/bin/env python3
"""Generate visuals for palmy-scripts pipeline outputs.

Creates:
- coverage_progress.png (sample & cluster coverage over iterations)
- rules_issues_progress.png (active/dead rules and yaraQA issues)
- sample_cluster_assignment.png (samples vs cluster assignment heatmap)
- cluster_feature_prevalence.png (clusters vs top-features prevalence heatmap)
- top_rules_hits.png (final top rule hit counts)

Run from repository root, e.g.:
  python3 palmy-scripts/visualize_pipeline.py --pipeline-dir palmy-scripts/file-pipeline
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np

try:
    # import helper from the same folder
    from pipeline_lib import extract_tokens
except Exception:
    def extract_tokens(path, max_bytes, max_tokens_per_sample):
        # fallback: simple substring search (less accurate)
        try:
            raw = Path(path).read_bytes()[:max_bytes]
            text = raw.decode("latin1", errors="ignore").lower()
            tokens = list({t for t in text.split() if len(t) >= 4})
            return tokens[:max_tokens_per_sample]
        except Exception:
            return []


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_iteration_metrics(iter_dir: Path) -> list[dict[str, Any]]:
    summary_path = iter_dir / "iteration_metrics.json"
    if summary_path.exists():
        return [read_json(summary_path)]
    return []


def gather_iterations(pipeline_dir: Path) -> list[dict[str, Any]]:
    final_summary = pipeline_dir / "final-results" / "pipeline_summary.json"
    if final_summary.exists():
        data = read_json(final_summary)
        return data.get("iteration_metrics", [])

    iterations_root = pipeline_dir / "iterations"
    records: list[dict[str, Any]] = []
    if iterations_root.exists():
        for d in sorted(iterations_root.iterdir()):
            if d.is_dir():
                p = d / "iteration_metrics.json"
                if p.exists():
                    records.append(read_json(p))
    return records


def plot_coverage(records: list[dict[str, Any]], out: Path) -> None:
    xs = [r["iteration"] for r in records]
    sample_cov = [r["sample_coverage"] for r in records]
    cluster_cov = [r["cluster_coverage"] for r in records]

    plt.figure(figsize=(8, 4.5))
    plt.plot(xs, sample_cov, marker="o", label="Sample coverage")
    plt.plot(xs, cluster_cov, marker="o", label="Cluster coverage")
    plt.ylim(0.0, 1.0)
    plt.xlabel("Iteration")
    plt.ylabel("Coverage")
    plt.title("Coverage Progress")
    plt.grid(alpha=0.3)
    plt.legend()
    out.joinpath("coverage_progress.png").parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(out / "coverage_progress.png", dpi=150)
    plt.close()


def plot_rules_and_issues(records: list[dict[str, Any]], out: Path) -> None:
    xs = [r["iteration"] for r in records]
    active = [r.get("active_rules", 0) for r in records]
    dead = [r.get("dead_rules", 0) for r in records]
    issues = [r.get("yaraqa_issues", 0) for r in records]

    plt.figure(figsize=(8, 4.5))
    plt.plot(xs, active, marker="o", label="Active rules")
    plt.plot(xs, dead, marker="o", label="Dead rules")
    plt.bar([x - 0.15 for x in xs], issues, width=0.3, alpha=0.6, label="yaraQA issues")
    plt.xlabel("Iteration")
    plt.ylabel("Count")
    plt.title("Rules and yaraQA Issues")
    plt.grid(alpha=0.2)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out / "rules_issues_progress.png", dpi=150)
    plt.close()


def plot_top_rules(final_eval: dict[str, Any], out: Path) -> None:
    top = final_eval.get("top_rules") or []
    if not top:
        return
    names = [t.get("rule") for t in top]
    hits = [t.get("hits", 0) for t in top]

    y_pos = np.arange(len(names))
    plt.figure(figsize=(7, max(3, len(names) * 0.5)))
    plt.barh(y_pos, hits, align="center")
    plt.yticks(y_pos, names)
    plt.xlabel("Hits")
    plt.title("Top rule hits (final)")
    plt.tight_layout()
    plt.savefig(out / "top_rules_hits.png", dpi=150)
    plt.close()


def plot_sample_cluster_assignment(grouping: dict[str, Any], out: Path) -> None:
    row_labels = grouping.get("row_labels", [])
    all_files = grouping.get("all_files", [])
    if not row_labels:
        return

    labels = np.array(row_labels)
    n_samples = labels.shape[0]
    clusters = int(max(labels.max() + 1, grouping.get("n_biclusters", 0)))
    # build assignment matrix
    M = np.zeros((n_samples, clusters), dtype=int)
    for i, c in enumerate(labels):
        if c >= 0 and c < clusters:
            M[i, int(c)] = 1

    # sort samples by label for visual clarity
    order = np.argsort(labels)
    M_sorted = M[order]

    plt.figure(figsize=(8, max(4, n_samples * 0.02)))
    plt.imshow(M_sorted, aspect="auto", cmap="tab20")
    plt.xlabel("Cluster")
    plt.ylabel("Samples (sorted by cluster)")
    plt.title("Sample → Cluster assignment")
    plt.colorbar(label="Assignment (1 = member)")
    plt.tight_layout()
    plt.savefig(out / "sample_cluster_assignment.png", dpi=150)
    plt.close()


def plot_cluster_feature_prevalence(grouping: dict[str, Any], out: Path, max_bytes: int, max_tokens: int) -> None:
    profiles = grouping.get("cluster_profiles", [])
    if not profiles:
        return

    # union of top features across clusters
    features = []
    for p in profiles:
        for f in p.get("top_features", []):
            if f not in features:
                features.append(f)

    if not features:
        return

    n_clusters = len(profiles)
    F = np.zeros((n_clusters, len(features)), dtype=float)

    for ci, profile in enumerate(profiles):
        sample_paths = profile.get("sample_paths", [])
        if not sample_paths:
            continue
        for fi, feat in enumerate(features):
            count = 0
            for sp in sample_paths:
                tokens = extract_tokens(Path(sp), max_bytes, max_tokens)
                if feat in tokens:
                    count += 1
            F[ci, fi] = count / max(1, len(sample_paths))

    plt.figure(figsize=(max(6, len(features) * 0.25), max(4, n_clusters * 0.6)))
    im = plt.imshow(F, aspect="auto", cmap="viridis", vmin=0.0, vmax=1.0)
    plt.colorbar(im, label="Prevalence (fraction of samples in cluster)")
    plt.yticks(range(n_clusters), [f"C{p.get('cluster_id')} ({p.get('sample_count')})" for p in profiles])
    # limit feature label length for readability
    labels = [f if len(f) <= 24 else f[:21] + "..." for f in features]
    plt.xticks(range(len(features)), labels, rotation=90)
    plt.title("Cluster × Feature prevalence (top features)")
    plt.tight_layout()
    plt.savefig(out / "cluster_feature_prevalence.png", dpi=150)
    plt.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Visualize palmy-scripts pipeline outputs")
    parser.add_argument("--pipeline-dir", default="palmy-scripts/file-pipeline", help="Pipeline folder (e.g. palmy-scripts/file-pipeline)")
    parser.add_argument("--out-dir", default="figures", help="Output folder (relative to pipeline-dir)")
    parser.add_argument("--max-bytes", type=int, default=20000)
    parser.add_argument("--max-tokens", type=int, default=280)
    args = parser.parse_args()

    pipeline_dir = Path(args.pipeline_dir)
    if not pipeline_dir.exists():
        print(f"Pipeline dir not found: {pipeline_dir}")
        return 2

    out = pipeline_dir / args.out_dir
    out.mkdir(parents=True, exist_ok=True)

    grouping_path = pipeline_dir / "bicluster" / "bicluster_grouping.json"
    if not grouping_path.exists():
        print("bicluster_grouping.json not found; cannot plot bicluster visuals")
        grouping = {}
    else:
        grouping = read_json(grouping_path)

    records = gather_iterations(pipeline_dir)
    if not records:
        print("No iteration metrics found; nothing to plot for iterations")
    else:
        plot_coverage(records, out)
        plot_rules_and_issues(records, out)

    final_eval_path = pipeline_dir / "final-results" / "final_eval.json"
    final_eval = {}
    if final_eval_path.exists():
        final_eval = read_json(final_eval_path)
        plot_top_rules(final_eval, out)

    if grouping:
        plot_sample_cluster_assignment(grouping, out)
        plot_cluster_feature_prevalence(grouping, out, args.max_bytes, args.max_tokens)

    print("Saved figures to:")
    for p in sorted(out.iterdir()):
        print(" -", p)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
