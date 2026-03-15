#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from pipeline_lib import (
    BiclusterParams,
    RuleSeedParams,
    build_initial_manifest,
    evaluate_rules_against_clusters,
    goal_reached,
    improve_manifest_from_feedback,
    load_yaraqa_issues,
    markdown_pipeline_summary,
    parse_categories,
    read_json,
    run_bicluster_grouping,
    run_yaraqa,
    summarize_yaraqa_issues,
    write_json,
    write_manifest_and_rules,
)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="End-to-end biclustering -> initial YARA -> yaraQA/eval iteration pipeline"
    )

    parser.add_argument("--samples-root", required=True, help="Dataset root folder")
    parser.add_argument("--categories", required=True, help="Comma-separated categories")
    parser.add_argument("--dataset-label", required=True, help="Label for outputs")
    parser.add_argument("--output-root", default="palmy-scripts", help="Root output folder")

    parser.add_argument("--max-files", type=int, default=6000)
    parser.add_argument("--max-bytes", type=int, default=20000)
    parser.add_argument("--max-tokens-per-sample", type=int, default=280)
    parser.add_argument("--max-features", type=int, default=900)
    parser.add_argument("--min-df", type=int, default=4)
    parser.add_argument("--n-biclusters", type=int, default=10)
    parser.add_argument("--max-cells", type=int, default=20000000)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--top-features-per-cluster", type=int, default=25)

    parser.add_argument("--strings-per-rule", type=int, default=6)
    parser.add_argument("--min-cluster-samples", type=int, default=5)
    parser.add_argument("--min-rule-strings", type=int, default=3)
    parser.add_argument("--threshold-ratio", type=float, default=0.67)

    parser.add_argument("--max-iterations", type=int, default=6)
    parser.add_argument("--target-sample-coverage", type=float, default=0.70)
    parser.add_argument("--target-cluster-coverage", type=float, default=0.85)
    parser.add_argument("--max-yaraqa-issues", type=int, default=10)

    parser.add_argument("--yara-timeout", type=int, default=20)
    parser.add_argument("--yaraqa-script", default="", help="Optional explicit path to yaraQA.py")
    parser.add_argument("--yaraqa-level", type=int, choices=[1, 2, 3])
    parser.add_argument("--ignore-performance", action="store_true")

    return parser


def write_bicluster_markdown_report(grouping: dict, output_path: Path) -> None:
    lines = [
        f"# Bicluster Grouping Report ({grouping['dataset']})",
        "",
        "## Matrix",
        f"- Files processed: **{grouping['files_processed']}**",
        f"- Shape: **{grouping['matrix_shape'][0]} × {grouping['matrix_shape'][1]}**",
        f"- Fit shape: **{grouping['fit_submatrix_shape'][0]} × {grouping['fit_submatrix_shape'][1]}**",
        f"- Sparsity: **{grouping['sparsity']:.4f}**",
        f"- Effective biclusters: **{grouping['n_biclusters']}**",
        "",
        "## Cluster Profiles",
    ]

    for profile in grouping.get("cluster_profiles", []):
        fam = ", ".join(f"{name}:{count}" for name, count in profile.get("top_families", [])[:3])
        feat = ", ".join(profile.get("top_features", [])[:8])
        lines.append(
            f"- C{profile['cluster_id']}: samples={profile['sample_count']}, features={profile['feature_count']}, density={profile['density']:.3f}, families={fam or 'none'}, top_features={feat or 'none'}"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    samples_root = Path(args.samples_root).resolve()
    categories = parse_categories(args.categories)
    output_root = Path(args.output_root).resolve()

    bicluster_dir = output_root / "bicluster"
    initial_rules_dir = output_root / "initial-rules"
    iterations_dir = output_root / "iterations"
    final_dir = output_root / "final-results"

    bicluster_dir.mkdir(parents=True, exist_ok=True)
    initial_rules_dir.mkdir(parents=True, exist_ok=True)
    iterations_dir.mkdir(parents=True, exist_ok=True)
    final_dir.mkdir(parents=True, exist_ok=True)

    bicluster_params = BiclusterParams(
        samples_root=samples_root,
        categories=categories,
        dataset_label=args.dataset_label,
        max_files=args.max_files,
        max_bytes=args.max_bytes,
        max_tokens_per_sample=args.max_tokens_per_sample,
        max_features=args.max_features,
        min_df=args.min_df,
        n_biclusters=args.n_biclusters,
        max_cells=args.max_cells,
        random_state=args.random_state,
        top_features_per_cluster=args.top_features_per_cluster,
    )

    grouping = run_bicluster_grouping(bicluster_params)
    grouping_json = bicluster_dir / "bicluster_grouping.json"
    write_json(grouping_json, grouping)
    write_bicluster_markdown_report(grouping, bicluster_dir / "bicluster_grouping_report.md")

    seed_params = RuleSeedParams(
        strings_per_rule=args.strings_per_rule,
        min_cluster_samples=args.min_cluster_samples,
        min_rule_strings=args.min_rule_strings,
        threshold_ratio=args.threshold_ratio,
    )

    manifest = build_initial_manifest(grouping, seed_params)
    if not manifest:
        raise RuntimeError("Unable to generate initial rules from biclusters with current thresholds")

    initial_manifest_path = initial_rules_dir / "rules_manifest.json"
    initial_rules_path = initial_rules_dir / "initial_cluster_rules.yar"
    write_manifest_and_rules(manifest, initial_manifest_path, initial_rules_path, stage="initial")

    cluster_mapping = grouping.get("cluster_mapping", {})
    iteration_records: list[dict] = []
    current_manifest = manifest
    target_reached = False

    yaraqa_script = Path(args.yaraqa_script).resolve() if args.yaraqa_script else None

    for iteration in range(1, args.max_iterations + 1):
        iter_dir = iterations_dir / f"iter_{iteration:02d}"
        rules_dir = iter_dir / "rules"
        rules_file = rules_dir / "cluster_rules.yar"
        manifest_file = iter_dir / "rules_manifest.json"

        write_manifest_and_rules(current_manifest, manifest_file, rules_file, stage=f"iter_{iteration}")

        eval_results = evaluate_rules_against_clusters(
            rules_file=rules_file,
            cluster_mapping=cluster_mapping,
            timeout_sec=args.yara_timeout,
        )
        write_json(iter_dir / "eval.json", eval_results)

        yaraqa_output = iter_dir / "yaraqa_issues.json"
        yaraqa_run = run_yaraqa(
            rules_dir=rules_dir,
            output_json=yaraqa_output,
            yaraqa_script=yaraqa_script,
            level=args.yaraqa_level,
            ignore_performance=args.ignore_performance,
        )
        write_json(iter_dir / "yaraqa_run.json", yaraqa_run)

        issues = load_yaraqa_issues(yaraqa_output)
        issue_summary = summarize_yaraqa_issues(issues)
        write_json(iter_dir / "yaraqa_summary.json", issue_summary)

        summary = eval_results.get("summary", {})
        record = {
            "iteration": iteration,
            "sample_coverage": float(summary.get("sample_coverage", 0.0)),
            "cluster_coverage": float(summary.get("cluster_coverage", 0.0)),
            "active_rules": int(summary.get("active_rules", 0)),
            "dead_rules": int(summary.get("dead_rules", 0)),
            "yaraqa_issues": int(issue_summary.get("total_issues", 0)),
        }
        iteration_records.append(record)
        write_json(iter_dir / "iteration_metrics.json", record)

        if goal_reached(
            eval_results,
            issue_summary,
            target_sample_coverage=args.target_sample_coverage,
            target_cluster_coverage=args.target_cluster_coverage,
            max_yaraqa_issues=args.max_yaraqa_issues,
        ):
            target_reached = True
            break

        next_manifest, changes = improve_manifest_from_feedback(
            current_manifest,
            eval_results,
            issues,
        )
        current_manifest = next_manifest
        write_json(iter_dir / "changes.json", changes)

    final_manifest_path = final_dir / "final_rules_manifest.json"
    final_rules_path = final_dir / "final_improved_rules.yar"
    write_manifest_and_rules(current_manifest, final_manifest_path, final_rules_path, stage="final")

    final_eval = evaluate_rules_against_clusters(
        rules_file=final_rules_path,
        cluster_mapping=cluster_mapping,
        timeout_sec=args.yara_timeout,
    )
    write_json(final_dir / "final_eval.json", final_eval)

    final_yaraqa_path = final_dir / "final_yaraqa_issues.json"
    final_yaraqa_run = run_yaraqa(
        rules_dir=final_dir,
        output_json=final_yaraqa_path,
        yaraqa_script=yaraqa_script,
        level=args.yaraqa_level,
        ignore_performance=args.ignore_performance,
    )
    write_json(final_dir / "final_yaraqa_run.json", final_yaraqa_run)

    final_issues = load_yaraqa_issues(final_yaraqa_path)
    final_issue_summary = summarize_yaraqa_issues(final_issues)
    write_json(final_dir / "final_yaraqa_summary.json", final_issue_summary)

    summary_payload = {
        "dataset_label": args.dataset_label,
        "samples_root": str(samples_root),
        "categories": categories,
        "target_reached": target_reached,
        "iterations_executed": len(iteration_records),
        "targets": {
            "sample_coverage": args.target_sample_coverage,
            "cluster_coverage": args.target_cluster_coverage,
            "max_yaraqa_issues": args.max_yaraqa_issues,
        },
        "initial_rules_file": str(initial_rules_path),
        "final_rules_file": str(final_rules_path),
        "final_eval_summary": final_eval.get("summary", {}),
        "final_yaraqa_summary": final_issue_summary,
        "iteration_metrics": iteration_records,
    }
    write_json(final_dir / "pipeline_summary.json", summary_payload)

    final_summary_md = markdown_pipeline_summary(
        dataset_label=args.dataset_label,
        categories=categories,
        samples_root=str(samples_root),
        iteration_records=iteration_records,
        final_manifest_count=len(current_manifest),
        final_rules_path=str(final_rules_path),
    )
    (final_dir / "pipeline_summary.md").write_text(final_summary_md, encoding="utf-8")

    print("Pipeline completed")
    print(f"- Bicluster grouping: {grouping_json}")
    print(f"- Initial rules: {initial_rules_path}")
    print(f"- Final rules: {final_rules_path}")
    print(f"- Final summary: {final_dir / 'pipeline_summary.json'}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
