"""Reproducible synthetic evaluation; no live AWS conclusions or novelty claims."""

import copy
import json
import math
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "backend"))
from app.engine import analyze, demo_dataset, simulate


def ndcg(order, relevance):
    def dcg(items):
        return sum(
            (2 ** relevance.get(item, 0) - 1) / math.log2(i + 2)
            for i, item in enumerate(items)
        )

    ideal = sorted(relevance, key=lambda item: -relevance[item])
    return dcg(order) / dcg(ideal) if dcg(ideal) else 0


def run():
    data = demo_dataset()
    started = time.perf_counter()
    result = analyze(data)
    duration = time.perf_counter() - started
    by_name = {i["name"]: i["id"] for i in data["identities"]}
    truth = {
        by_name[name]
        for name in ["developer", "deployment", "payments-worker", "vendor-bridge"]
    }
    relevance = {
        by_name[name]: value
        for name, value in {
            "payments-worker": 3,
            "developer": 2,
            "deployment": 1,
            "vendor-bridge": 1,
            "metrics-reader": 0,
        }.items()
    }
    no_events = analyze({**data, "events": []})
    basic = sorted(
        {
            f["identity_id"]
            for f in no_events["findings"]
            if "Broad permission" in f["title"] or "External principal" in f["title"]
        }
    )
    graph = [p["start"] for p in no_events["paths"]]
    enriched = [p["start"] for p in result["paths"]]
    metrics = {}
    for name, ranking in [
        ("independent_configuration_rules", basic),
        ("graph", graph),
        ("graph_with_events", enriched),
    ]:
        predicted = set(ranking)
        tp, fp, fn = (
            len(predicted & truth),
            len(predicted - truth),
            len(truth - predicted),
        )
        negatives = len(data["identities"]) - len(truth)
        metrics[name] = {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "precision": tp / (tp + fp) if tp + fp else 0,
            "recall": tp / len(truth),
            "false_positive_rate": fp / negatives,
            "ndcg": ndcg(ranking, relevance),
            "ranking": ranking,
        }
    expected_routes = [
        [
            by_name["developer"],
            by_name["deployment"],
            by_name["payments-worker"],
            data["resources"][0]["id"],
        ],
        [by_name["deployment"], by_name["payments-worker"], data["resources"][0]["id"]],
        [by_name["payments-worker"], data["resources"][0]["id"]],
        [by_name["vendor-bridge"], data["resources"][0]["id"]],
    ]
    valid = sum(p["nodes"] in expected_routes for p in result["paths"])
    remediation = simulate(
        data,
        by_name["payments-worker"],
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "cloudwatch:GetMetricData",
                    "Resource": "*",
                }
            ]
        },
    )
    scalability = []
    for size in [10, 50, 100, 250]:
        scaled = copy.deepcopy(data)
        template = scaled["identities"][3]
        scaled["identities"] = [
            {**template, "id": template["id"] + str(i), "name": f"benign-{i}"}
            for i in range(size)
        ]
        start = time.perf_counter()
        scaled_result = analyze(scaled)
        scalability.append(
            {
                "identities": size,
                "seconds": time.perf_counter() - start,
                "paths": len(scaled_result["paths"]),
            }
        )
    return {
        "dataset": "Synthetic five-identity nine-scenario demonstration",
        "labels": "Policy-defined reachability to finance resource; graded ranking prioritizes observed signals. Labels are constructed, not independent real-world threat truth.",
        "methods": metrics,
        "path_validity": valid / len(result["paths"]),
        "expected_path_count": len(expected_routes),
        "actual_path_count": len(result["paths"]),
        "analysis_seconds": duration,
        "remediation_removed_paths": len(remediation["removed_path_ids"]),
        "scalability": scalability,
        "limitations": [
            "Tiny synthetic demonstration; no statistical generalization",
            "Behavior labels intentionally align with inserted signals; not evidence of research superiority",
            "Scalability measures benign identities with two assets, not dense adversarial graphs",
            "No live AWS simulator oracle available",
        ],
    }


if __name__ == "__main__":
    output = run()
    destination = (
        pathlib.Path(__file__).resolve().parents[1] / "docs" / "evaluation-results.json"
    )
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output, indent=2))
