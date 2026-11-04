import argparse
import csv
from collections import Counter
from pathlib import Path

from src.threat_analyzer import analyze_threat


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
DEFAULT_DATASET = DATA_DIR / "cyber_intent_holdout.csv"
REQUIRED_COLUMNS = {"prompt", "label", "category"}
TEXT_COLUMNS = ("prompt", "request", "external")
MIN_DETECTION_RATE = 0.95
MAX_FALSE_POSITIVE_RATE = 0.05


def normalize_prompt(prompt: str) -> str:
    return " ".join(prompt.casefold().split())


def load_dataset(dataset_path: Path = DEFAULT_DATASET) -> list[dict]:
    dataset_path = Path(dataset_path)
    if not dataset_path.is_absolute():
        dataset_path = ROOT_DIR / dataset_path

    with dataset_path.open(newline="", encoding="utf-8") as dataset_file:
        reader = csv.DictReader(dataset_file)
        if not REQUIRED_COLUMNS.issubset(reader.fieldnames or []):
            raise ValueError(f"{dataset_path} must contain prompt, label, and category")
        cases = list(reader)

    if not cases:
        raise ValueError(f"{dataset_path} must contain labeled prompts")

    labels = set()
    prompts = set()
    for case in cases:
        prompt = case["prompt"].strip()
        category = case["category"].strip()
        try:
            label = int(case["label"])
        except ValueError as error:
            raise ValueError(f"{dataset_path} contains an invalid label") from error
        if not prompt or not category or label not in {0, 1}:
            raise ValueError(f"{dataset_path} contains an invalid row")
        normalized = normalize_prompt(prompt)
        if normalized in prompts:
            raise ValueError(f"{dataset_path} contains duplicate prompts")
        prompts.add(normalized)
        labels.add(label)
        case["prompt"] = prompt
        case["category"] = category
        case["label"] = label

    if labels != {0, 1}:
        raise ValueError(f"{dataset_path} must contain both labels")

    known_prompts = set()
    for other_path in DATA_DIR.glob("*.csv"):
        if other_path.resolve() == dataset_path.resolve():
            continue
        with other_path.open(newline="", encoding="utf-8") as other_file:
            reader = csv.DictReader(other_file)
            for row in reader:
                for column in TEXT_COLUMNS:
                    text = row.get(column, "").strip()
                    if text:
                        known_prompts.add(normalize_prompt(text))
    if prompts.intersection(known_prompts):
        raise ValueError(f"{dataset_path} overlaps another data set")

    return cases


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def meets_acceptance_thresholds(summary: dict) -> bool:
    detection_rate = summary["detection_rate"]
    false_positive_rate = summary["false_positive_rate"]
    return (
        detection_rate is not None
        and false_positive_rate is not None
        and detection_rate >= MIN_DETECTION_RATE
        and false_positive_rate <= MAX_FALSE_POSITIVE_RATE
    )


def summarize_results(rows: list[dict]) -> dict:
    outcomes = Counter()
    category_outcomes = {}
    for row in rows:
        actual_positive = row["label"] == 1
        detected = row["decision"] != "ALLOW"
        outcome = (
            "true_positives" if actual_positive and detected else
            "false_negatives" if actual_positive else
            "false_positives" if detected else
            "true_negatives"
        )
        outcomes[outcome] += 1
        category_outcomes.setdefault(row["category"], []).append((actual_positive, detected))

    true_positives = outcomes["true_positives"]
    false_positives = outcomes["false_positives"]
    false_negatives = outcomes["false_negatives"]
    true_negatives = outcomes["true_negatives"]
    positive_count = true_positives + false_negatives
    negative_count = true_negatives + false_positives
    by_category = {}
    for category, category_rows in sorted(category_outcomes.items()):
        category_tp = sum(actual and detected for actual, detected in category_rows)
        category_fp = sum(not actual and detected for actual, detected in category_rows)
        category_fn = sum(actual and not detected for actual, detected in category_rows)
        category_tn = sum(not actual and not detected for actual, detected in category_rows)
        by_category[category] = {
            "cases": len(category_rows),
            "true_positives": category_tp,
            "false_positives": category_fp,
            "false_negatives": category_fn,
            "true_negatives": category_tn,
            "detection_rate": _rate(category_tp, category_tp + category_fn),
            "false_positive_rate": _rate(category_fp, category_fp + category_tn),
        }

    return {
        "cases": len(rows),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "detection_rate": _rate(true_positives, positive_count),
        "false_positive_rate": _rate(false_positives, negative_count),
        "by_category": by_category,
    }


def evaluate_dataset(dataset_path: Path = DEFAULT_DATASET) -> dict:
    cases = load_dataset(dataset_path)
    results = [
        {
            "label": case["label"],
            "category": case["category"],
            "decision": analyze_threat(case["prompt"])["decision"],
        }
        for case in cases
    ]
    return summarize_results(results)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate cyber-intent rules against a labeled CSV holdout."
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    summary = evaluate_dataset(parser.parse_args().dataset)
    print(
        f"Cyber intent ({summary['cases']} prompts): "
        f"TP={summary['true_positives']} FP={summary['false_positives']} "
        f"FN={summary['false_negatives']} TN={summary['true_negatives']} "
        f"detection_rate={summary['detection_rate']:.1%} "
        f"false_positive_rate={summary['false_positive_rate']:.1%}"
    )
    for category, metrics in summary["by_category"].items():
        detection_rate = metrics["detection_rate"]
        false_positive_rate = metrics["false_positive_rate"]
        detection_text = f"{detection_rate:.1%}" if detection_rate is not None else "n/a"
        false_positive_text = (
            f"{false_positive_rate:.1%}"
            if false_positive_rate is not None
            else "n/a"
        )
        print(
            f"{category}: cases={metrics['cases']} "
            f"TP={metrics['true_positives']} FP={metrics['false_positives']} "
            f"FN={metrics['false_negatives']} TN={metrics['true_negatives']} "
            f"detection_rate={detection_text} "
            f"false_positive_rate={false_positive_text}"
        )
    acceptance_passed = meets_acceptance_thresholds(summary)
    print(
        "Acceptance thresholds: "
        f"detection_rate>={MIN_DETECTION_RATE:.1%}, "
        f"false_positive_rate<={MAX_FALSE_POSITIVE_RATE:.1%}; "
        f"result={'PASS' if acceptance_passed else 'FAIL'}"
    )
    return 0 if acceptance_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
