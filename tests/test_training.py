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