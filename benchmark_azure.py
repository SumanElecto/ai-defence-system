import argparse
import csv
import os
from collections import Counter
from math import ceil, floor
from pathlib import Path
from statistics import mean, median
from time import perf_counter

from dotenv import load_dotenv

from src.openai_adapter import model_adapter_from_environment
from src.secure_model import ModelAdapter, ModelInput, secure_generate


ROOT_DIR = Path(__file__).resolve().parent
DATASET_FILE = ROOT_DIR / "data" / "security_benchmark.csv"
RESULTS_FILE = ROOT_DIR / "data" / "azure_benchmark_results.csv"
DATASET_LABELS = {
    "benign": 0,
    "direct_injection": 1,
    "indirect_injection": 1,
    "malicious_cyber": 1,
    "defensive_cybersecurity": 0,
}
RESULT_COLUMNS = (
    "case",
    "category",
    "iteration",
    "label",
    "decision",
    "alert_detected",
    "model_status",
    "model_called",
    "forwarding_allowed",
    "latency_ms",
    "model_latency_ms",
    "gateway_overhead_ms",
    "response_length",
    "error_type",
)


def _normalize_prompt(prompt: str) -> str:
    return " ".join(prompt.casefold().split())


def load_benchmark_cases(dataset_path: Path = DATASET_FILE) -> list[dict]:
    dataset_path = Path(dataset_path)
    required_columns = {"id", "category", "request", "external", "label"}
    cases = []
    category_counts = Counter()
    seen_ids = set()
    seen_prompts = set()

    with dataset_path.open(newline="", encoding="utf-8") as dataset_file:
        reader = csv.DictReader(dataset_file)
        if not required_columns.issubset(reader.fieldnames or []):
            raise ValueError(f"{dataset_path} must contain {sorted(required_columns)}")
        for row in reader:
            case_id = row["id"].strip()
            category = row["category"].strip()
            request = row["request"].strip()
            external = row["external"].strip()
            if not case_id or case_id in seen_ids:
                raise ValueError(f"{dataset_path} contains a missing or duplicate id")
            if category not in DATASET_LABELS:
                raise ValueError(f"{dataset_path} contains an unknown category")
            if not request:
                raise ValueError(f"{dataset_path} contains an empty request")
            try:
                label = int(row["label"])
            except ValueError as error:
                raise ValueError(f"{dataset_path} contains an invalid label") from error
            if label != DATASET_LABELS[category]:
                raise ValueError(f"{dataset_path} has a label inconsistent with its category")
            if (category == "indirect_injection") != bool(external):
                raise ValueError("Only indirect injection cases must have external content")

            for prompt in (request, external):
                if not prompt:
                    continue
                normalized = _normalize_prompt(prompt)
                if normalized in seen_prompts:
                    raise ValueError(f"{dataset_path} contains duplicate prompt text")
                seen_prompts.add(normalized)

            seen_ids.add(case_id)
            category_counts[category] += 1
            cases.append({
                "id": case_id,
                "category": category,
                "request": request,
                "external": external,
                "label": label,
                "model_eligible": label == 0,
            })

    if set(category_counts) != set(DATASET_LABELS):
        raise ValueError(f"{dataset_path} must contain all benchmark categories")
    if any(not 30 <= count <= 50 for count in category_counts.values()):
        raise ValueError("Each benchmark category must contain 30 to 50 prompts")

    existing_prompts = set()
    for existing_path in (ROOT_DIR / "data").glob("*.csv"):
        if existing_path.resolve() == dataset_path.resolve():
            continue
        with existing_path.open(newline="", encoding="utf-8") as existing_file:
            reader = csv.DictReader(existing_file)
            if "prompt" not in (reader.fieldnames or []):
                continue
            existing_prompts.update(
                _normalize_prompt(row["prompt"])
                for row in reader
                if row.get("prompt", "").strip()
            )
    if seen_prompts.intersection(existing_prompts):
        raise ValueError(f"{dataset_path} overlaps another data set")

    return cases


CASES = load_benchmark_cases()


class TimedAdapter:
    def __init__(self, adapter: ModelAdapter):
        self.adapter = adapter
        self.elapsed_ms: float | None = None

    def generate(self, model_input: ModelInput) -> str:
        started = perf_counter()
        try:
            return self.adapter.generate(model_input)
        finally:
            self.elapsed_ms = (perf_counter() - started) * 1000


def percentile(values: list[float], percentile_value: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile_value
    lower = floor(position)
    upper = ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _confusion_counts(rows: list[dict]) -> dict[str, int]:
    return {
        "true_positives": sum(
            row["label"] == 1 and row["alert_detected"] for row in rows
        ),
        "false_positives": sum(
            row["label"] == 0 and row["alert_detected"] for row in rows
        ),
        "false_negatives": sum(
            row["label"] == 1 and not row["alert_detected"] for row in rows
        ),
        "true_negatives": sum(
            row["label"] == 0 and not row["alert_detected"] for row in rows
        ),
    }


def summarize_results(rows: list[dict]) -> dict:
    confusion = _confusion_counts(rows)
    positive_count = confusion["true_positives"] + confusion["false_negatives"]
    negative_count = confusion["true_negatives"] + confusion["false_positives"]
    model_calls = sum(row["model_called"] for row in rows)
    successful_responses = sum(row["model_status"] == "responded" for row in rows)
    successful_latencies = [
        row["model_latency_ms"]
        for row in rows
        if row["model_status"] == "responded"
    ]
    gateway_overheads = [row["gateway_overhead_ms"] for row in rows]
    error_types = Counter(row["error_type"] for row in rows if row["error_type"])

    by_category = {}
    for category in sorted({row["category"] for row in rows}):
        category_rows = [row for row in rows if row["category"] == category]
        category_counts = _confusion_counts(category_rows)
        category_positive = (
            category_counts["true_positives"] + category_counts["false_negatives"]
        )
        category_negative = (
            category_counts["true_negatives"] + category_counts["false_positives"]
        )
        by_category[category] = {
            "cases": len(category_rows),
            **category_counts,
            "detection_rate": (
                category_counts["true_positives"] / category_positive
                if category_positive
                else None
            ),
            "false_positive_rate": (
                category_counts["false_positives"] / category_negative
                if category_negative
                else None
            ),
        }

    return {
        "runs": len(rows),
        **confusion,
        "detection_rate": (
            confusion["true_positives"] / positive_count if positive_count else None
        ),
        "false_positive_rate": (
            confusion["false_positives"] / negative_count if negative_count else None
        ),
        "model_calls": model_calls,
        "successful_responses": successful_responses,
        "model_errors": sum(row["model_status"] == "model_error" for row in rows),
        "security_errors": sum(
            bool(row["error_type"]) and row["model_status"] != "model_error"
            for row in rows
        ),
        "successful_response_rate": (
            successful_responses / model_calls if model_calls else None
        ),
        "error_types": dict(error_types),
        "azure_response_latency_avg_ms": (
            mean(successful_latencies) if successful_latencies else None
        ),
        "azure_response_latency_median_ms": (
            median(successful_latencies) if successful_latencies else None
        ),
        "azure_response_latency_p95_ms": percentile(successful_latencies, 0.95),
        "gateway_overhead_avg_ms": (
            mean(gateway_overheads) if gateway_overheads else None
        ),
        "gateway_overhead_median_ms": (
            median(gateway_overheads) if gateway_overheads else None
        ),
        "by_category": by_category,
    }


def run_benchmark(
    model: ModelAdapter | None,
    repeats: int = 1,
    cases: list[dict] | None = None,
) -> dict:
    if repeats < 1:
        raise ValueError("repeats must be positive")
    benchmark_cases = CASES if cases is None else cases
    rows = []
    for iteration in range(1, repeats + 1):
        for case in benchmark_cases:
            timed_model = (
                TimedAdapter(model)
                if model is not None and case["model_eligible"]
                else None
            )
            started = perf_counter()
            result = secure_generate(case["request"], case["external"], timed_model)
            total_ms = (perf_counter() - started) * 1000
            model_ms = timed_model.elapsed_ms if timed_model is not None else None
            security = result.get("security") or {}
            response = result.get("model_response")
            decision = result["final_decision"]
            model_called = result["forwarded_to_model"]
            gateway_overhead_ms = max(0.0, total_ms - (model_ms or 0.0))
            rows.append({
                "case": case["id"],
                "category": case["category"],
                "iteration": iteration,
                "label": case["label"],
                "decision": decision,
                "alert_detected": decision != "ALLOW",
                "model_status": result["model_status"],
                "model_called": model_called,
                "forwarding_allowed": security.get("forwarding_allowed", False),
                "latency_ms": round(total_ms, 3),
                "model_latency_ms": round(model_ms, 3) if model_ms is not None else "",
                "gateway_overhead_ms": round(gateway_overhead_ms, 3),
                "response_length": len(response) if response is not None else "",
                "error_type": (
                    result.get("model_error_type")
                    or security.get("error_type")
                    or security.get("trusted_request_analysis", {}).get("error_type")
                    or ""
                ),
            })
    return {
        "summary": summarize_results(rows),
        "results": rows,
    }


def write_results(rows: list[dict]) -> None:
    with Path(RESULTS_FILE).open("w", newline="", encoding="utf-8") as results_file:
        writer = csv.DictWriter(results_file, fieldnames=RESULT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def _format_rate(value: float | None) -> str:
    return f"{value:.1%}" if value is not None else "n/a"


def _format_ms(value: float | None) -> str:
    return f"{value:.3f}" if value is not None else "n/a"


def print_results(rows: list[dict]) -> None:
    for row in rows:
        error_type = row["error_type"] or "none"
        response_length = row["response_length"]
        response_length = response_length if response_length != "" else "n/a"
        print(
            f"DEBUG: case={row['case']} category={row['category']} "
            f"label={row['label']} decision={row['decision']} "
            f"alert_detected={'yes' if row['alert_detected'] else 'no'} "
            f"model_status={row['model_status']} "
            f"forwarded={'yes' if row['model_called'] else 'no'} "
            f"forwarding_allowed={'yes' if row['forwarding_allowed'] else 'no'} "
            f"total_latency_ms={row['latency_ms']:.3f} "
            f"model_latency_ms={_format_ms(row['model_latency_ms'] or None)} "
            f"gateway_overhead_ms={row['gateway_overhead_ms']:.3f} "
            f"response_length={response_length} error_type={error_type}"
        )


def print_summary(summary: dict) -> None:
    print(
        "Security metrics: "
        f"TP={summary['true_positives']} FP={summary['false_positives']} "
        f"FN={summary['false_negatives']} TN={summary['true_negatives']} "
        f"detection_rate={_format_rate(summary['detection_rate'])} "
        f"false_positive_rate={_format_rate(summary['false_positive_rate'])}"
    )
    print(
        "Model metrics: "
        f"calls={summary['model_calls']} "
        f"successful_responses={summary['successful_responses']} "
        f"model_errors={summary['model_errors']} "
        f"security_errors={summary['security_errors']} "
        f"success_rate={_format_rate(summary['successful_response_rate'])}"
    )
    print(
        "Azure response latency ms (successful responses): "
        f"avg={_format_ms(summary['azure_response_latency_avg_ms'])} "
        f"median={_format_ms(summary['azure_response_latency_median_ms'])} "
        f"p95={_format_ms(summary['azure_response_latency_p95_ms'])}"
    )
    print(
        "Gateway overhead ms: "
        f"avg={_format_ms(summary['gateway_overhead_avg_ms'])} "
        f"median={_format_ms(summary['gateway_overhead_median_ms'])}"
    )
    for category, metrics in summary["by_category"].items():
        print(
            f"Category {category}: cases={metrics['cases']} "
            f"TP={metrics['true_positives']} FP={metrics['false_positives']} "
            f"FN={metrics['false_negatives']} TN={metrics['true_negatives']} "
            f"detection_rate={_format_rate(metrics['detection_rate'])} "
            f"false_positive_rate={_format_rate(metrics['false_positive_rate'])}"
        )


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Benchmark Azure through the security gateway.")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--dry-run", action="store_true", help="Analyze locally without a provider.")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")

    provider = os.environ.get("MODEL_PROVIDER", "").strip().lower()
    model = None
    if not args.dry_run:
        if provider not in {"azure_openai", "azure_foundry"}:
            parser.error("Set MODEL_PROVIDER to azure_openai or azure_foundry")
        try:
            model = model_adapter_from_environment()
        except Exception as error:
            parser.error(f"Azure configuration failed ({type(error).__name__})")
        if model is None:
            parser.error("Required Azure environment settings are missing")

    report = run_benchmark(model, args.repeats)
    rows = report["results"]
    print_results(rows)
    print_summary(report["summary"])
    write_results(rows)
    print(f"CSV written: {RESULTS_FILE}")
    return int(bool(report["summary"]["model_errors"]))


if __name__ == "__main__":
    raise SystemExit(main())