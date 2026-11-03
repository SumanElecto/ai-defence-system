
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
SPLIT_NAMES = ("train", "validation", "test")


def normalize_prompt(prompt: object) -> str:
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("Every prompt must be non-empty text")
    return " ".join(prompt.casefold().split())


def load_splits() -> dict[str, pd.DataFrame]:
    splits = {}
    prompt_owners = {}

    for split_name in SPLIT_NAMES:
        split_path = DATA_DIR / f"{split_name}.csv"
        dataset = pd.read_csv(split_path)

        if not {"prompt", "label"}.issubset(dataset.columns):
            raise ValueError(f"{split_path} must contain prompt and label columns")
        if dataset.empty:
            raise ValueError(f"{split_path} must contain prompts")
        if dataset["label"].isna().any() or not set(dataset["label"]).issubset({0, 1}):
            raise ValueError(f"{split_path} labels must be 0 (benign) or 1 (injection)")
        if set(dataset["label"]) != {0, 1}:
            raise ValueError(f"{split_path} must contain both labels")

        try:
            normalized_prompts = dataset["prompt"].map(normalize_prompt)
        except ValueError as error:
            raise ValueError(f"{split_path} contains an invalid prompt") from error
        if normalized_prompts.duplicated().any():
            raise ValueError(f"{split_path} contains duplicate prompts")

        for prompt in normalized_prompts:
            if prompt in prompt_owners:
                raise ValueError(
                    f"Prompt appears in both {prompt_owners[prompt]} and {split_name}"
                )
            prompt_owners[prompt] = split_name

        dataset["label"] = dataset["label"].astype(int)
        splits[split_name] = dataset

    return splits


def build_model() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2)
        )),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        ))
    ])


def evaluate_model(model: Pipeline, dataset: pd.DataFrame, split_name: str) -> dict[str, int]:
    labels = dataset["label"]
    predictions = model.predict(dataset["prompt"])
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    true_negatives, false_positives, false_negatives, true_positives = matrix.ravel()

    print(f"\n{split_name.title()} results ({len(dataset)} prompts):")
    print(classification_report(
        labels,
        predictions,
        labels=[0, 1],
        target_names=["benign", "injection"],
        zero_division=0
    ))
    print("Confusion matrix (rows=actual, columns=predicted; benign, injection):")
    print(matrix)
    print(f"False positives (benign flagged): {false_positives}")
    print(f"False negatives (injection missed): {false_negatives}")

    return {
        "true_negatives": int(true_negatives),
        "false_positives": int(false_positives),
        "false_negatives": int(false_negatives),
        "true_positives": int(true_positives),
    }


def main() -> None:
    splits = load_splits()
    model = build_model()
    model.fit(splits["train"]["prompt"], splits["train"]["label"])

    evaluate_model(model, splits["validation"], "Validation")
    test_counts = evaluate_model(model, splits["test"], "Independent test")

    model_path = ROOT_DIR / "prompt_injection_model.pkl"
    joblib.dump(model, model_path)
    print(f"\nModel saved to {model_path}")
    print(
        "Independent test summary: "
        f"FP={test_counts['false_positives']}, "
        f"FN={test_counts['false_negatives']}"
    )


if __name__ == "__main__":
    main()
