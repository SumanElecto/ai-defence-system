# AI Security Threat Detection and Defense System

A local Streamlit prototype that screens submitted text for prompt-injection and cyber-threat indicators. It combines regular-expression rules, a TF-IDF/logistic-regression classifier, and a separate rule-based threat analyzer. It does not use a remote generative model.

## Run Locally

Use Python 3.13 through 3.15.2. The CI matrix covers Python 3.13, 3.14, and 3.15.2; local validation has been run on 3.15.2. Install the pinned runtime and test dependencies:

```bash
python -m pip install -r requirements.txt
```

Start the app from the repository root:

```bash
streamlit run app.py
```

The model artifact, `prompt_injection_model.pkl`, is loaded locally by the detector and must be present in the repository root.

## Detection Flow

- The prompt-injection detector combines regex matches with a trained classifier.
- The threat analyzer checks for explicit cyber-abuse indicators and ambiguous cyber language.
- The application returns `BLOCK` for explicit threat-analyzer blocks or high-confidence injection categories, `REVIEW` for ambiguous or otherwise suspicious results, and `ALLOW` when no known indicators match.

`ALLOW` means that these known indicators did not match; it does not establish that a prompt is safe. The rule and model layers are heuristic and can disagree, especially on quoted attack text.

## Dataset and Evaluation

The curated dataset has three fixed, disjoint CSV files, each with `prompt,label` columns:

| File | Prompts | Balance |
|---|---:|---:|
| `data/train.csv` | 60 | 30 benign, 30 injection |
| `data/validation.csv` | 30 | 15 benign, 15 injection |
| `data/test.csv` | 30 | 15 benign, 15 injection |

Label `1` means the prompt itself attempts an instruction override or hidden-prompt extraction. Label `0` includes benign requests, legitimate defensive cybersecurity questions, and quoted attacks that are being discussed rather than followed. The held-out test set should not be used to tune the model.

Train and evaluate the classifier from the repository root:

```bash
python src/train.py
```

The trainer fits only on the training split, reports precision, recall, F1, confusion matrices, false positives, and false negatives for validation and test, then writes the model artifact. It also checks labels, empty prompts, and exact normalized duplicates across splits.

Latest recorded independent-test result: 28 of 30 prompts classified correctly, with 2 false positives and 0 false negatives (0.93 accuracy, 0.94 macro F1). Both false positives were benign prompts quoting attack language. This is a small, hand-curated test set, so these numbers are a smoke check, not a reliable estimate of real-world performance. The reported metrics evaluate the classifier alone, not the combined rule-based application.

For a separate adversarial audit, run:

```bash
python -m src.evaluate_adversarial
```

This checks that `data/adversarial_test.csv` has no exact normalized overlap with the training, validation, or standard test splits. It reports classifier-only errors and end-to-end errors; `REVIEW` counts as an alert for the end-to-end false-positive/false-negative summary. Review is still distinct from an automatic block, so the script also reports the final `BLOCK`, `REVIEW`, and `ALLOW` counts.

Run the test suite:

```bash
python -m pytest -v
```

GitHub Actions runs the test suite on each configured Python version.

## Project Layout

- `app.py`: Streamlit interface and final decision aggregation.
- `src/detector.py`: prompt-injection rules and trained classifier.
- `src/threat_analyzer.py`: explicit and ambiguous cyber-threat analysis.
- `src/train.py`: split validation, model training, and holdout evaluation.
- `src/evaluate_adversarial.py`: non-overlapping adversarial evaluation for the classifier and full decision pipeline.
- `data/`: fixed training, validation, independent test, and adversarial test datasets.
- `tests/`: detector, integration, and dataset-integrity tests.

## Security Notes

- Treat prompts and dataset examples as untrusted content.
- `joblib.load` can execute code. Only load the trusted model artifact produced by this project; never load user-supplied model files.
- The dataset and rules are too small and heuristic to provide production-grade security guarantees. Validate on representative, independently collected data before relying on detection outcomes.