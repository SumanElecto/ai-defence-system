from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from app import evaluate_security
from src.detector import ml_model
from src.train import load_splits, normalize_prompt


ROOT_DIR = Path(__file__).resolve().parents[1]
ADVERSARIAL_PATH = ROOT_DIR / "data" / "adversarial_test.csv"


def load_adversarial_data() -> pd.DataFrame:
    dataset = pd.read_csv(ADVERSARIAL_PATH)
    required_columns = {"prompt", "label", "category"}

    if not required_columns.issubset(dataset.columns):
        raise ValueError("Adversarial data must contain prompt, label, and category")
    if dataset.empty or dataset["label"].isna().any():
        raise ValueError("Adversarial data must contain labeled prompts")
    if not set(dataset["label"]).issubset({0, 1}) or set(dataset["label"]) != {0, 1}:
        raise ValueError("Adversarial labels must include both 0 and 1")
    if dataset["category"].isna().any() or dataset["category"].str.strip().eq("").any():
        raise ValueError("Every adversarial prompt must have a category")

    normalized = dataset["prompt"].map(normalize_prompt)
    if normalized.duplicated().any():
        raise ValueError("Adversarial data contains duplicate prompts")

    known_prompts = {
        normalize_prompt(prompt)
        for split in load_splits().values()
        for prompt in split["prompt"]
    }
    if known_prompts.intersection(normalized):
        raise ValueError("Adversarial data overlaps an existing dataset split")

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


def main() -> None:
    dataset = load_adversarial_data()
    model_predictions = [int(label) for label in ml_model.predict(dataset["prompt"])]
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
        ["BLOCK", "REVIEW", "ALLOW"], fill_value=0
    ))


if __name__ == "__main__":
    main()