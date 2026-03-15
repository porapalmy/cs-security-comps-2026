from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.cluster import SpectralCoclustering
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction.text import CountVectorizer


STOPWORDS = {
    "function", "return", "false", "true", "null", "this", "that", "with", "from",
    "while", "class", "public", "private", "static", "const", "let", "var",
    "html", "head", "body", "script", "style", "div", "span", "href", "http", "https",
    "window", "document", "index", "main", "error", "warning", "debug", "info",
}
TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]{4,64}")
RULE_RE = re.compile(r"^\s*rule\s+([A-Za-z0-9_]+)", flags=re.MULTILINE)


@dataclass
class BiclusterParams:
    samples_root: Path
    categories: list[str]
    dataset_label: str
    max_files: int
    max_bytes: int
    max_tokens_per_sample: int
    max_features: int
    min_df: int
    n_biclusters: int
    max_cells: int
    random_state: int
    top_features_per_cluster: int


@dataclass
class RuleSeedParams:
    strings_per_rule: int
    min_cluster_samples: int
    min_rule_strings: int
    threshold_ratio: float


def parse_categories(categories_csv: str) -> list[str]:
    return [item.strip() for item in categories_csv.split(",") if item.strip()]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def iter_files(samples_root: Path, categories: list[str]):
    for category in categories:
        category_path = samples_root / category
        if not category_path.exists():
            continue
        for dirpath, _, filenames in os.walk(category_path):
            for filename in filenames:
                yield Path(dirpath) / filename


def infer_family(file_path: Path, samples_root: Path) -> str:
    try:
        rel = file_path.relative_to(samples_root)
        return rel.parts[0] if len(rel.parts) > 1 else file_path.parent.name
    except Exception:
        return file_path.parent.name


def extract_tokens(file_path: Path, max_bytes: int, max_tokens_per_sample: int) -> list[str]:
    try:
        raw = file_path.read_bytes()[:max_bytes]
    except Exception:
        return []

    text = raw.decode("latin1", errors="ignore").lower()
    matches = TOKEN_RE.findall(text)

    result: list[str] = []
    seen: set[str] = set()
    for token in matches:
        if token in seen:
            continue
        if token in STOPWORDS:
            continue
        if token.isdigit():
            continue
        if len(token) < 4:
            continue
        if token.count("/") > 6:
            continue
        if token.count(".") > 6:
            continue
        seen.add(token)
        result.append(token)
        if len(result) >= max_tokens_per_sample:
            break

    return result


def make_matrix(docs: list[str], max_features: int, min_df: int):
    vectorizer = CountVectorizer(
        tokenizer=str.split,
        preprocessor=None,
        token_pattern=None,
        lowercase=False,
        binary=True,
        max_features=max_features,
        min_df=min_df,
        dtype=np.uint8,
    )
    matrix = vectorizer.fit_transform(docs)
    feature_names = np.array(vectorizer.get_feature_names_out())
    return matrix, feature_names


def fit_coclustering(matrix_fit, requested_clusters: int, random_state: int):
    max_clusters = min(requested_clusters, matrix_fit.shape[0], matrix_fit.shape[1])
    if max_clusters < 2:
        raise RuntimeError("Not enough rows/columns to perform biclustering")

    current = max_clusters
    model = None
    while current >= 2:
        candidate = SpectralCoclustering(n_clusters=current, random_state=random_state)
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", ConvergenceWarning)
            candidate.fit(matrix_fit)
        has_convergence_warning = any(issubclass(item.category, ConvergenceWarning) for item in captured)
        if has_convergence_warning and current > 2:
            current -= 1
            continue
        model = candidate
        break

    if model is None:
        raise RuntimeError("Unable to fit coclustering model")

    return model, current


def run_bicluster_grouping(params: BiclusterParams) -> dict[str, Any]:
    files = sorted(iter_files(params.samples_root, params.categories))
    if params.max_files and len(files) > params.max_files:
        files = files[: params.max_files]

    if not files:
        raise RuntimeError(
            f"No files found in {params.samples_root} for categories: {params.categories}"
        )

    docs: list[str] = []
    families: list[str] = []
    for file_path in files:
        tokens = extract_tokens(file_path, params.max_bytes, params.max_tokens_per_sample)
        docs.append(" ".join(tokens))
        families.append(infer_family(file_path, params.samples_root))

    if not any(doc.strip() for doc in docs):
        raise RuntimeError("No extractable tokens found in dataset under current extraction settings")

    matrix, feature_names = make_matrix(docs, params.max_features, params.min_df)

    n_samples, n_features = matrix.shape
    total_cells = n_samples * n_features
    if total_cells > params.max_cells:
        raise RuntimeError(f"Matrix too large: {total_cells} > max-cells={params.max_cells}")

    row_hits = np.asarray(matrix.sum(axis=1)).ravel().astype(int)
    col_hits = np.asarray(matrix.sum(axis=0)).ravel().astype(int)

    nonzero_rows = np.where(row_hits > 0)[0]
    nonzero_cols = np.where(col_hits > 0)[0]

    if len(nonzero_rows) < 2 or len(nonzero_cols) < 2:
        raise RuntimeError(
            "Not enough non-zero rows/cols for biclustering "
            f"(rows={len(nonzero_rows)}, cols={len(nonzero_cols)})"
        )

    matrix_fit = matrix[nonzero_rows][:, nonzero_cols]
    feature_names_fit = feature_names[nonzero_cols]

    model, used_clusters = fit_coclustering(matrix_fit, params.n_biclusters, params.random_state)

    row_labels_full = np.full(n_samples, -1, dtype=int)
    col_labels_full = np.full(n_features, -1, dtype=int)
    row_labels_full[nonzero_rows] = model.row_labels_
    col_labels_full[nonzero_cols] = model.column_labels_

    cluster_mapping: dict[str, list[str]] = {}
    cluster_profiles: list[dict[str, Any]] = []

    for cluster_id in range(used_clusters):
        row_idx = np.where(row_labels_full == cluster_id)[0]
        col_idx = np.where(col_labels_full == cluster_id)[0]

        sample_paths = [str(files[i]) for i in row_idx]
        cluster_mapping[str(cluster_id)] = sample_paths

        if len(row_idx) == 0 or len(col_idx) == 0:
            top_features: list[str] = []
            density = 0.0
        else:
            cluster_sub = matrix[np.ix_(row_idx, col_idx)]
            prevalence = np.asarray(cluster_sub.mean(axis=0)).ravel()
            order = np.argsort(-prevalence)
            selected = col_idx[order[: params.top_features_per_cluster]]
            top_features = [str(feature_names[i]) for i in selected]
            density = float(cluster_sub.mean())

        fam_counts = Counter(families[i] for i in row_idx).most_common(5)

        cluster_profiles.append(
            {
                "cluster_id": int(cluster_id),
                "sample_count": int(len(row_idx)),
                "feature_count": int(len(col_idx)),
                "density": density,
                "top_families": fam_counts,
                "top_features": top_features,
                "sample_paths": sample_paths,
            }
        )

    unassigned_rows = np.where(row_labels_full == -1)[0]
    if len(unassigned_rows):
        cluster_mapping["unassigned"] = [str(files[i]) for i in unassigned_rows]

    summary = {
        "dataset": params.dataset_label,
        "samples_root": str(params.samples_root),
        "categories": params.categories,
        "files_processed": int(len(files)),
        "matrix_shape": [int(n_samples), int(n_features)],
        "fit_submatrix_shape": [int(matrix_fit.shape[0]), int(matrix_fit.shape[1])],
        "sparsity": float(1.0 - (int(matrix.sum()) / total_cells)),
        "n_biclusters": int(used_clusters),
        "excluded_zero_rows": int(n_samples - matrix_fit.shape[0]),
        "excluded_zero_cols": int(n_features - matrix_fit.shape[1]),
        "cluster_profiles": cluster_profiles,
        "cluster_mapping": cluster_mapping,
        "all_files": [str(path) for path in files],
        "families": families,
        "row_labels": row_labels_full.tolist(),
    }
    return summary


def token_is_yara_friendly(token: str) -> bool:
    if len(token) < 4 or len(token) > 80:
        return False
    if any(ch in token for ch in ["\n", "\r", "\t", "\x00"]):
        return False
    if token.count("/") > 6:
        return False
    return True


def sanitize_rule_name(name: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    if not name:
        name = "ClusterRule"
    if name[0].isdigit():
        name = f"R_{name}"
    return name


def build_initial_manifest(grouping: dict[str, Any], seed_params: RuleSeedParams) -> list[dict[str, Any]]:
    manifest: list[dict[str, Any]] = []

    profiles = grouping.get("cluster_profiles", [])
    profiles = sorted(profiles, key=lambda item: item.get("sample_count", 0), reverse=True)

    for profile in profiles:
        sample_count = int(profile.get("sample_count", 0))
        if sample_count < seed_params.min_cluster_samples:
            continue

        cluster_id = int(profile.get("cluster_id", -1))
        top_families = profile.get("top_families", [])
        family_name = top_families[0][0] if top_families else f"cluster_{cluster_id}"

        features = [item for item in profile.get("top_features", []) if token_is_yara_friendly(str(item))]
        dedup_features: list[str] = []
        seen: set[str] = set()
        for feat in features:
            if feat in seen:
                continue
            seen.add(feat)
            dedup_features.append(feat)
            if len(dedup_features) >= seed_params.strings_per_rule:
                break

        if len(dedup_features) < seed_params.min_rule_strings:
            continue

        k = int(math.ceil(len(dedup_features) * seed_params.threshold_ratio))
        k = max(1, min(k, len(dedup_features)))

        rule_name = sanitize_rule_name(f"Cluster_{cluster_id}_{family_name}_Seed")
        manifest.append(
            {
                "rule_name": rule_name,
                "cluster_id": cluster_id,
                "sample_count": sample_count,
                "strings": dedup_features,
                "min_match_count": k,
            }
        )

    return manifest


def escape_yara_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_rules_from_manifest(manifest: list[dict[str, Any]], stage: str) -> str:
    lines = [
        "/*",
        f" Auto-generated YARA rules (stage: {stage})",
        " Generated by palmy-scripts iterative pipeline.",
        "*/",
        "",
    ]

    for entry in manifest:
        rule_name = entry["rule_name"]
        strings = entry.get("strings", [])
        min_match = int(entry.get("min_match_count", 1))

        if not strings:
            continue

        lines.append(f"rule {rule_name}")
        lines.append("{")
        lines.append("  meta:")
        lines.append(f"    stage = \"{stage}\"")
        lines.append(f"    cluster_id = \"{entry.get('cluster_id', 'na')}\"")
        lines.append(f"    sample_count = \"{entry.get('sample_count', 'na')}\"")
        lines.append("  strings:")
        for index, value in enumerate(strings, start=1):
            lines.append(f"    $s{index} = \"{escape_yara_string(str(value))}\" ascii")
        lines.append("  condition:")
        if min_match >= len(strings):
            lines.append("    all of ($s*)")
        else:
            lines.append(f"    {min_match} of ($s*)")
        lines.append("}")
        lines.append("")

    return "\n".join(lines) + "\n"


def write_manifest_and_rules(
    manifest: list[dict[str, Any]],
    manifest_path: Path,
    rules_path: Path,
    stage: str,
) -> None:
    write_json(manifest_path, manifest)
    rules_path.parent.mkdir(parents=True, exist_ok=True)
    rules_path.write_text(render_rules_from_manifest(manifest, stage), encoding="utf-8")


def collect_declared_rules(rules_file: Path) -> list[str]:
    text = rules_file.read_text(encoding="utf-8", errors="ignore")
    return sorted(set(RULE_RE.findall(text)))


def run_yara_match(rules_file: Path, sample_file: str, timeout_sec: int) -> tuple[list[str], str]:
    try:
        proc = subprocess.run(
            ["yara", str(rules_file), sample_file],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("The 'yara' executable was not found in PATH.")
    except subprocess.TimeoutExpired:
        return [], f"timeout: {sample_file}"

    errors = proc.stderr.strip()
    if proc.returncode not in (0, 1) and errors:
        return [], errors

    matched_rules: list[str] = []
    stdout = proc.stdout.strip()
    if stdout:
        for line in stdout.splitlines():
            parts = line.split()
            if parts:
                matched_rules.append(parts[0])

    return matched_rules, errors


def evaluate_rules_against_clusters(
    rules_file: Path,
    cluster_mapping: dict[str, list[str]],
    timeout_sec: int = 20,
) -> dict[str, Any]:
    declared_rules = collect_declared_rules(rules_file)

    rule_hits: dict[str, dict[str, Any]] = {
        rule: {"count": 0, "files": []} for rule in declared_rules
    }

    per_cluster: dict[str, dict[str, Any]] = {}
    errors: list[str] = []

    unique_samples: list[str] = []
    seen_samples: set[str] = set()

    for cluster_id, files in cluster_mapping.items():
        per_cluster[str(cluster_id)] = {"files": files, "matches": {}}
        for file_path in files:
            if file_path not in seen_samples:
                seen_samples.add(file_path)
                unique_samples.append(file_path)

            matched_rules, err = run_yara_match(rules_file, file_path, timeout_sec)
            if err:
                errors.append(f"{file_path}: {err}")

            for rule_name in matched_rules:
                if rule_name not in rule_hits:
                    rule_hits[rule_name] = {"count": 0, "files": []}
                rule_hits[rule_name]["count"] += 1
                rule_hits[rule_name]["files"].append(file_path)
                cluster_match = per_cluster[str(cluster_id)]["matches"].setdefault(rule_name, [])
                cluster_match.append(file_path)

    samples_with_hits = 0
    for sample in unique_samples:
        has_match = any(sample in entry["files"] for entry in rule_hits.values())
        if has_match:
            samples_with_hits += 1

    clusters_with_hits = 0
    for cluster_data in per_cluster.values():
        has_cluster_hit = any(cluster_data["matches"].get(rule) for rule in cluster_data["matches"])
        if has_cluster_hit:
            clusters_with_hits += 1

    total_samples = len(unique_samples)
    total_clusters = len(per_cluster)

    total_hits = int(sum(entry["count"] for entry in rule_hits.values()))
    active_rules = [name for name, item in rule_hits.items() if item["count"] > 0]
    dead_rules = [name for name, item in rule_hits.items() if item["count"] == 0]

    top_rules = sorted(
        [{"rule": name, "hits": int(data["count"])} for name, data in rule_hits.items()],
        key=lambda item: item["hits"],
        reverse=True,
    )[:20]

    result = {
        "rules": rule_hits,
        "per_cluster": per_cluster,
        "summary": {
            "samples_total": int(total_samples),
            "samples_with_hits": int(samples_with_hits),
            "sample_coverage": float(samples_with_hits / total_samples) if total_samples else 0.0,
            "clusters_total": int(total_clusters),
            "clusters_with_hits": int(clusters_with_hits),
            "cluster_coverage": float(clusters_with_hits / total_clusters) if total_clusters else 0.0,
            "total_hits": total_hits,
            "declared_rules": len(declared_rules),
            "active_rules": len(active_rules),
            "dead_rules": len(dead_rules),
            "dead_rule_names": dead_rules,
            "top_rules": top_rules,
        },
        "errors": errors,
    }
    return result


def resolve_default_yaraqa_script() -> Path:
    return Path(__file__).resolve().parents[1] / "rule-dev" / "tools" / "yaraQA" / "yaraQA.py"


def run_yaraqa(
    rules_dir: Path,
    output_json: Path,
    yaraqa_script: Path | None = None,
    level: int | None = None,
    ignore_performance: bool = False,
) -> dict[str, Any]:
    script = yaraqa_script or resolve_default_yaraqa_script()
    if not script.exists():
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"yaraQA script not found at {script}",
            "output_path": str(output_json),
        }

    output_json.parent.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, str(script), "-d", str(rules_dir), "-o", str(output_json)]
    if level is not None:
        cmd += ["-l", str(level)]
    if ignore_performance:
        cmd.append("--ignore-performance")

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "output_path": str(output_json),
        "cmd": cmd,
    }


def load_yaraqa_issues(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = read_json(path)
    except Exception:
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def summarize_yaraqa_issues(issues: list[dict[str, Any]]) -> dict[str, Any]:
    type_counts: dict[str, int] = defaultdict(int)
    level_counts: dict[str, int] = defaultdict(int)

    for issue in issues:
        issue_type = str(issue.get("type", "other")).lower()
        level = str(issue.get("level", "unknown"))
        type_counts[issue_type] += 1
        level_counts[level] += 1

    return {
        "total_issues": len(issues),
        "by_type": dict(sorted(type_counts.items())),
        "by_level": dict(sorted(level_counts.items(), key=lambda item: item[0])),
    }


def normalize_string_by_issue(value: str, issue_id: str, issue_type: str) -> str:
    updated = value

    if len(updated) < 4:
        updated = updated + ("_" * (4 - len(updated)))

    if issue_id == "NC1" and updated.isalpha():
        updated = updated + " "

    if issue_id in {"PA2", "SV1"} and len(updated.strip()) < 4:
        updated = updated.strip() + "____"
        updated = updated[:8]

    if updated in {"&&", "||", ";", "|"}:
        updated = f" {updated} "

    if issue_type == "performance" and len(updated) < 4:
        updated = updated + "____"

    return updated[:80]


def improve_manifest_from_feedback(
    manifest: list[dict[str, Any]],
    eval_results: dict[str, Any],
    yaraqa_issues: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    next_manifest: list[dict[str, Any]] = []
    issue_map: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for issue in yaraqa_issues:
        rule_name = str(issue.get("rule", ""))
        if rule_name:
            issue_map[rule_name].append(issue)

    rule_hits = {
        name: int(data.get("count", 0))
        for name, data in eval_results.get("rules", {}).items()
        if isinstance(data, dict)
    }

    changes = {
        "rules_changed": 0,
        "threshold_relaxed": 0,
        "strings_modified": 0,
        "strings_removed": 0,
    }

    for rule in manifest:
        updated = {
            "rule_name": rule["rule_name"],
            "cluster_id": int(rule.get("cluster_id", -1)),
            "sample_count": int(rule.get("sample_count", 0)),
            "strings": [str(item) for item in rule.get("strings", [])],
            "min_match_count": int(rule.get("min_match_count", 1)),
        }

        hit_count = int(rule_hits.get(updated["rule_name"], 0))
        before_strings = list(updated["strings"])
        before_threshold = updated["min_match_count"]

        if hit_count == 0 and updated["min_match_count"] > 1:
            updated["min_match_count"] -= 1
        elif hit_count == 0 and len(updated["strings"]) > 3:
            updated["strings"] = updated["strings"][:-1]
        elif hit_count < 3 and updated["min_match_count"] > 1:
            updated["min_match_count"] -= 1

        for issue in issue_map.get(updated["rule_name"], []):
            issue_id = str(issue.get("id", ""))
            issue_type = str(issue.get("type", ""))
            element = issue.get("element")
            if isinstance(element, dict):
                value = str(element.get("value", ""))
                if value and value in updated["strings"]:
                    replacement = normalize_string_by_issue(value, issue_id, issue_type)
                    replacement = replacement.strip("\x00\n\r")
                    index = updated["strings"].index(value)
                    updated["strings"][index] = replacement
            elif issue_id == "RE1" and len(updated["strings"]) > 3:
                updated["strings"] = updated["strings"][:-1]

        cleaned_strings: list[str] = []
        seen: set[str] = set()
        for token in updated["strings"]:
            candidate = token.strip("\x00\n\r")
            if len(candidate) < 4:
                candidate = candidate + ("_" * (4 - len(candidate)))
            candidate = candidate[:80]
            if not token_is_yara_friendly(candidate):
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            cleaned_strings.append(candidate)

        if len(cleaned_strings) < 2:
            cleaned_strings = before_strings[:2] if len(before_strings) >= 2 else before_strings

        updated["strings"] = cleaned_strings
        updated["min_match_count"] = max(1, min(updated["min_match_count"], len(updated["strings"])))

        if updated["strings"] != before_strings or updated["min_match_count"] != before_threshold:
            changes["rules_changed"] += 1
        if updated["min_match_count"] < before_threshold:
            changes["threshold_relaxed"] += 1
        if len(updated["strings"]) < len(before_strings):
            changes["strings_removed"] += len(before_strings) - len(updated["strings"])
        if updated["strings"] != before_strings:
            changes["strings_modified"] += 1

        next_manifest.append(updated)

    return next_manifest, changes


def goal_reached(
    eval_results: dict[str, Any],
    issue_summary: dict[str, Any],
    target_sample_coverage: float,
    target_cluster_coverage: float,
    max_yaraqa_issues: int,
) -> bool:
    summary = eval_results.get("summary", {})
    sample_coverage = float(summary.get("sample_coverage", 0.0))
    cluster_coverage = float(summary.get("cluster_coverage", 0.0))
    issues_total = int(issue_summary.get("total_issues", 0))

    return (
        sample_coverage >= target_sample_coverage
        and cluster_coverage >= target_cluster_coverage
        and issues_total <= max_yaraqa_issues
    )


def markdown_pipeline_summary(
    dataset_label: str,
    categories: list[str],
    samples_root: str,
    iteration_records: list[dict[str, Any]],
    final_manifest_count: int,
    final_rules_path: str,
) -> str:
    lines = [
        f"# Iterative Bicluster-to-YARA Pipeline Summary ({dataset_label})",
        "",
        "## Dataset",
        f"- Samples root: `{samples_root}`",
        f"- Categories: `{', '.join(categories)}`",
        "",
        "## Iteration Metrics",
        "",
        "| Iteration | Sample Coverage | Cluster Coverage | Active Rules | Dead Rules | yaraQA Issues |",
        "|---:|---:|---:|---:|---:|---:|",
    ]

    for item in iteration_records:
        lines.append(
            f"| {item['iteration']} | {item['sample_coverage']:.4f} | {item['cluster_coverage']:.4f} | {item['active_rules']} | {item['dead_rules']} | {item['yaraqa_issues']} |"
        )

    lines.extend(
        [
            "",
            "## Final Output",
            f"- Final manifest rules: **{final_manifest_count}**",
            f"- Final rules file: `{final_rules_path}`",
            "",
            "## Notes",
            "- Initial rules are seeded from spectral co-cluster feature signatures.",
            "- Each iteration runs evaluation + yaraQA feedback before rule updates.",
            "- Improvement step currently uses deterministic heuristic rewrites.",
            "",
        ]
    )

    return "\n".join(lines)
