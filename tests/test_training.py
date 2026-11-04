from collections import Counter
from pathlib import Path

import pandas as pd

from src.evaluate_adversarial import (
    decision_outcome_matrix,
    load_adversarial_data,
    summarize_decision_rates,
)
from src.evaluate_cyber_intent import (
    load_dataset as load_cyber_intent_dataset,
    meets_acceptance_thresholds,
    summarize_results as summarize_cyber_intent_results,
)
from src.train import load_splits


def test_training_splits_are_balanced_and_disjoint():
    splits = load_splits()

    assert {name: len(dataset) for name, dataset in splits.items()} == {
        "train": 60,
        "validation": 30,
        "test": 30,
    }
    for dataset in splits.values():
        expected_count = len(dataset) // 2
        assert set(dataset["label"].value_counts().items()) == {
            (0, expected_count),
            (1, expected_count),
        }


def test_held_out_data_covers_quoted_attacks_and_defensive_security():
    splits = load_splits()
    held_out_prompts = " ".join(
        prompt
        for split_name in ("validation", "test")
        for prompt in splits[split_name]["prompt"].str.casefold()
    )

    assert "quoted" in held_out_prompts
    assert "vulnerability" in held_out_prompts


def test_adversarial_set_is_balanced_and_disjoint():
    dataset = load_adversarial_data()

    assert len(dataset) == 48
    assert dataset["label"].value_counts().to_dict() == {0: 24, 1: 24}
    assert dataset["category"].nunique() == 8


def test_robustness_set_is_balanced_and_disjoint():
    dataset = load_adversarial_data(Path("data/robustness_test.csv"))

    assert len(dataset) == 48
    assert dataset["label"].value_counts().to_dict() == {0: 24, 1: 24}
    assert dataset["category"].nunique() == 8
    assert set(dataset["category"].value_counts()) == {6}


def test_five_attack_families_are_balanced_and_disjoint():
    dataset = load_adversarial_data(Path("data/attack_families_test.csv"))

    assert len(dataset) == 20
    assert dataset["label"].value_counts().to_dict() == {0: 10, 1: 10}
    assert dataset["category"].nunique() == 5
    assert set(dataset["category"].value_counts()) == {4}


def test_system_rates_use_the_correct_denominators():
    dataset = pd.DataFrame({"label": [0, 0, 1, 1]})

    rates = summarize_decision_rates(dataset, ["ALLOW", "REVIEW", "BLOCK", "ALLOW"])

    assert rates["false_alarms"] == 1
    assert rates["false_alarm_rate"] == 0.5
    assert rates["missed_attacks"] == 1
    assert rates["missed_attack_rate"] == 0.5
    assert rates["review_rate"] == 0.25
    assert rates["automatic_block_rate"] == 0.25
    assert rates["attack_block_rate"] == 0.5


def test_decision_matrix_keeps_allow_review_and_block_separate():
    dataset = pd.DataFrame({"label": [0, 0, 1, 1]})

    matrix = decision_outcome_matrix(dataset, ["ALLOW", "REVIEW", "BLOCK", "ALLOW"])

    assert list(matrix.columns) == ["ALLOW", "REVIEW", "BLOCK"]
    assert list(matrix.loc["actual benign"]) == [1, 1, 0]
    assert list(matrix.loc["actual injection"]) == [1, 0, 1]


def test_cyber_intent_development_and_holdout_sets_are_balanced_and_disjoint():
    development = load_cyber_intent_dataset(Path("data/cyber_intent_dev.csv"))
    regression = load_cyber_intent_dataset(Path("data/cyber_intent_regression.csv"))
    holdout = load_cyber_intent_dataset()

    for dataset in (development, regression, holdout):
        assert len(dataset) == 60
        assert Counter(row["label"] for row in dataset) == {0: 30, 1: 30}
    development_prompts = {row["prompt"].casefold() for row in development}
    regression_prompts = {row["prompt"].casefold() for row in regression}
    holdout_prompts = {row["prompt"].casefold() for row in holdout}
    assert development_prompts.isdisjoint(regression_prompts)
    assert development_prompts.isdisjoint(holdout_prompts)
    assert regression_prompts.isdisjoint(holdout_prompts)


def test_cyber_intent_metrics_count_review_as_detection():
    rows = [
        {"label": 1, "category": "malicious", "decision": "REVIEW"},
        {"label": 1, "category": "malicious", "decision": "ALLOW"},
        {"label": 0, "category": "defensive", "decision": "BLOCK"},
        {"label": 0, "category": "defensive", "decision": "ALLOW"},
    ]

    summary = summarize_cyber_intent_results(rows)

    assert summary["true_positives"] == 1
    assert summary["false_positives"] == 1
    assert summary["false_negatives"] == 1
    assert summary["true_negatives"] == 1


def test_cyber_intent_acceptance_thresholds():
    assert meets_acceptance_thresholds({
        "detection_rate": 0.95,
        "false_positive_rate": 0.05,
    })
    assert not meets_acceptance_thresholds({
        "detection_rate": 0.94,
        "false_positive_rate": 0.05,
    })
    assert not meets_acceptance_thresholds({
        "detection_rate": 0.95,
        "false_positive_rate": 0.06,
    })