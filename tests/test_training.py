import pandas as pd

from src.evaluate_adversarial import (
    decision_outcome_matrix,
    load_adversarial_data,
    summarize_decision_rates,
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
    dataset = load_adversarial_data("data/robustness_test.csv")

    assert len(dataset) == 48
    assert dataset["label"].value_counts().to_dict() == {0: 24, 1: 24}
    assert dataset["category"].nunique() == 8
    assert set(dataset["category"].value_counts()) == {6}


def test_five_attack_families_are_balanced_and_disjoint():
    dataset = load_adversarial_data("data/attack_families_test.csv")

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
    assert matrix.loc["actual benign"].to_list() == [1, 1, 0]
    assert matrix.loc["actual injection"].to_list() == [1, 0, 1]