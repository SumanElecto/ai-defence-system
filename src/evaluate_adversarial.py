from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from src.detector import ml_model
from src.security import evaluate_security
from src.train import load_splits, normalize_prompt


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
ADVERSARIAL_PATH = ROOT_DIR / "data" / "adversarial_test.csv"
ROBUSTNESS_PATH = ROOT_DIR / "data" / "robustness_test.csv"
ATTACK_FAMILIES_PATH = ROOT_DIR / "data" / "attack_families_test.csv"
DECISION_ORDER = ("ALLOW", "REVIEW", "BLOCK")


def load_adversarial_data(dataset_path: Path = ADVERSARIAL_PATH) -> pd.DataFrame:
    dataset_path = Path(dataset_path)
    if not dataset_path.is_absolute():
        dataset_path = ROOT_DIR / dataset_path

    dataset = pd.read_csv(dataset_path)
    required_columns = {"prompt", "label", "category"}

    if not required_columns.issubset(dataset.columns):
        raise ValueError(f"{dataset_path} must contain prompt, label, and category")
    if dataset.empty or dataset["label"].isna().any():
        raise ValueError(f"{dataset_path} must contain labeled prompts")
    if not set(dataset["label"]).issubset({0, 1}) or set(dataset["label"]) != {0, 1}:
        raise ValueError(f"{dataset_path} labels must include both 0 and 1")
    if dataset["category"].isna().any() or dataset["category"].str.strip().eq("").any():
        raise ValueError(f"Every prompt in {dataset_path} must have a category")

    normalized = dataset["prompt"].map(normalize_prompt)
    if normalized.duplicated().any():
        raise ValueError(f"{dataset_path} contains duplicate prompts")

    known_prompts = {
        normalize_prompt(prompt)
        for split in load_splits().values()
        for prompt in split["prompt"]
    }
    for other_path in (ADVERSARIAL_PATH, ROBUSTNESS_PATH, ATTACK_FAMILIES_PATH):
        if other_path.resolve() == dataset_path.resolve() or not other_path.exists():
            continue
        other_dataset = pd.read_csv(other_path)
        known_prompts.update(other_dataset["prompt"].map(normalize_prompt))

    if known_prompts.intersection(normalized):
        raise ValueError(f"{dataset_path} overlaps another dataset split")

    dataset["label"] = dataset["label"].astype(int)
    return dataset


def report_predictions(
    dataset: pd.DataFrame,
    predictions: list[int],
    evaluation_name: str,
) -> None:
    labels = dataset["label"]
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    true_negatives, false_positives, false_negatives, true_positives = matrix.ravel()

    print(f"\n{evaluation_name} ({len(dataset)} prompts):")
    print(classification_report(
        labels,
        predictions,
        labels=[0, 1],
        target_names=["benign", "injection"],
        zero_division=0,
    ))
    print("Confusion matrix (rows=actual, columns=predicted; benign, injection):")
    print(matrix)
    print(
        f"TN={true_negatives}, FP={false_positives}, "
        f"FN={false_negatives}, TP={true_positives}"
    )

    evaluated = dataset.assign(prediction=predictions)
    for error_name, mask in (
        ("False positives", (evaluated["label"] == 0) & (evaluated["prediction"] == 1)),
        ("False negatives", (evaluated["label"] == 1) & (evaluated["prediction"] == 0)),
    ):
        errors = evaluated.loc[mask]
        print(f"{error_name} ({len(errors)}):")
        for _, row in errors.iterrows():
            detail = row.get("decision", row["prediction"])
            print(f"  [{row['category']}; result={detail}] {row['prompt']}")


def summarize_decision_rates(
    dataset: pd.DataFrame,
    decisions: list[str],
) -> dict[str, int | float]:
    if len(dataset) != len(decisions):
        raise ValueError("Each prompt must have exactly one system decision")
    if not set(decisions).issubset({"ALLOW", "REVIEW", "BLOCK"}):
        raise ValueError("System decisions must be ALLOW, REVIEW, or BLOCK")

    labels = dataset["label"]
    decision_series = pd.Series(decisions, index=dataset.index)
    prompt_count = len(dataset)
    benign_count = int((labels == 0).sum())
    injection_count = int((labels == 1).sum())
    false_alarms = int(((labels == 0) & (decision_series != "ALLOW")).sum())
    missed_attacks = int(((labels == 1) & (decision_series == "ALLOW")).sum())
    review_count = int((decision_series == "REVIEW").sum())
    automatic_blocks = int((decision_series == "BLOCK").sum())
    attack_blocks = int(((labels == 1) & (decision_series == "BLOCK")).sum())

    return {
        "prompt_count": prompt_count,
        "benign_count": benign_count,
        "injection_count": injection_count,
        "false_alarms": false_alarms,
        "false_alarm_rate": false_alarms / benign_count if benign_count else 0.0,
        "missed_attacks": missed_attacks,
        "missed_attack_rate": missed_attacks / injection_count if injection_count else 0.0,
        "review_count": review_count,
        "review_rate": review_count / prompt_count if prompt_count else 0.0,
        "automatic_blocks": automatic_blocks,
        "automatic_block_rate": automatic_blocks / prompt_count if prompt_count else 0.0,
        "attack_blocks": attack_blocks,
        "attack_block_rate": attack_blocks / injection_count if injection_count else 0.0,
    }


def decision_outcome_matrix(dataset: pd.DataFrame, decisions: list[str]) -> pd.DataFrame:
    if len(dataset) != len(decisions):
        raise ValueError("Each prompt must have exactly one system decision")
    if not set(decisions).issubset(DECISION_ORDER):
        raise ValueError("System decisions must be ALLOW, REVIEW, or BLOCK")

    labels = dataset["label"]
    decision_series = pd.Series(decisions, index=dataset.index)
    rows = {}
    for label, label_name in ((0, "actual benign"), (1, "actual injection")):
        rows[label_name] = [
            int(((labels == label) & (decision_series == decision)).sum())
            for decision in DECISION_ORDER
        ]
    return pd.DataFrame.from_dict(rows, orient="index", columns=DECISION_ORDER)


def report_decision_rates(dataset: pd.DataFrame, decisions: list[str]) -> None:
    rates = summarize_decision_rates(dataset, decisions)

    print("\nEnd-to-end operational rates:")
    print(
        f"False alarms (benign BLOCK or REVIEW): {rates['false_alarms']}/"
        f"{rates['benign_count']} ({rates['false_alarm_rate']:.1%})"
    )
    print(
        f"Missed attacks (injection ALLOW): {rates['missed_attacks']}/"
        f"{rates['injection_count']} ({rates['missed_attack_rate']:.1%})"
    )
    print(
        f"Review rate (all prompts): {rates['review_count']}/"
        f"{rates['prompt_count']} ({rates['review_rate']:.1%})"
    )
    print(
        f"Automatic block rate (all prompts): {rates['automatic_blocks']}/"
        f"{rates['prompt_count']} ({rates['automatic_block_rate']:.1%})"
    )
    print(
        f"Automatic block rate (injection prompts): {rates['attack_blocks']}/"
        f"{rates['injection_count']} ({rates['attack_block_rate']:.1%})"
    )


def report_family_results(dataset: pd.DataFrame, decisions: list[str]) -> None:
    evaluated = dataset.assign(decision=decisions)
    print("\nEnd-to-end results by attack family:")

    for family, group in evaluated.groupby("category", sort=True):
        attacks = group[group["label"] == 1]
        benign = group[group["label"] == 0]
        detected_attacks = int((attacks["decision"] != "ALLOW").sum())
        missed_attacks = int((attacks["decision"] == "ALLOW").sum())
        false_alarms = int((benign["decision"] != "ALLOW").sum())
        attack_blocks = int((attacks["decision"] == "BLOCK").sum())
        attack_count = len(attacks)
        benign_count = len(benign)
        detection_rate = detected_attacks / attack_count if attack_count else 0.0
        false_alarm_rate = false_alarms / benign_count if benign_count else 0.0
        block_rate = attack_blocks / attack_count if attack_count else 0.0
        outcome_counts = group["decision"].value_counts().reindex(
            DECISION_ORDER, fill_value=0
        )

        print(
            f"{family}: ALLOW={outcome_counts['ALLOW']}, "
            f"REVIEW={outcome_counts['REVIEW']}, BLOCK={outcome_counts['BLOCK']}; "
            f"attack detection {detected_attacks}/{attack_count} "
            f"({detection_rate:.1%}), missed {missed_attacks}, "
            f"automatic blocks {attack_blocks}/{attack_count} ({block_rate:.1%}), "
            f"benign false alarms {false_alarms}/{benign_count} ({false_alarm_rate:.1%})"
        )
        for _, row in group.iterrows():
            actual_label = "injection" if row["label"] == 1 else "benign"
            print(f"  actual={actual_label}, decision={row['decision']}: {row['prompt']}")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate the detector on an adversarial CSV set.")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=ADVERSARIAL_PATH,
        help="CSV with prompt, label, and category columns",
    )
    dataset_path = parser.parse_args().dataset
    dataset = load_adversarial_data(dataset_path)
    if dataset_path.resolve() == ADVERSARIAL_PATH.resolve():
        print("Dataset status: tuning regression set; not an untouched benchmark.")
    elif dataset_path.resolve() == ATTACK_FAMILIES_PATH.resolve():
        print("Dataset status: used to guide detector changes; treat as regression data, not an independent holdout.")
    else:
        print(f"Dataset status: separate holdout from {dataset_path.name}.")
    print(
        "Safety note: prompts and embedded/Base64 payloads are passed as text; "
        "the evaluator does not decode or execute them."
    )

    if ml_model is None:
        print("\nClassifier-only results unavailable: model failed to load.")
    else:
        try:
            model_predictions = [
                int(label) for label in ml_model.predict(dataset["prompt"])
            ]
        except Exception as error:
            model_predictions = None
            print(
                "\nClassifier-only results unavailable: "
                f"inference failed ({type(error).__name__})."
            )
        if model_predictions is not None:
            report_predictions(dataset, model_predictions, "Classifier-only results")

    decisions = [
        evaluate_security(prompt)["final_decision"]
        for prompt in dataset["prompt"]
    ]
    system_predictions = [int(decision != "ALLOW") for decision in decisions]
    system_dataset = dataset.assign(decision=decisions)
    report_predictions(
        system_dataset,
        system_predictions,
        "End-to-end results (BLOCK or REVIEW counts as an alert)",
    )
    print("\nEnd-to-end decision counts:")
    print(pd.Series(decisions).value_counts().reindex(
        DECISION_ORDER, fill_value=0
    ))
    print("\nEnd-to-end decision matrix (actual rows; ALLOW, REVIEW, BLOCK columns):")
    print(decision_outcome_matrix(dataset, decisions).to_string())
    report_decision_rates(dataset, decisions)
    report_family_results(dataset, decisions)


if __name__ == "__main__":
    main()