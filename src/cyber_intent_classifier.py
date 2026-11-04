import csv
import re
from functools import lru_cache
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
TRAINING_FILES = (DATA_DIR / "cyber_intent_dev.csv",)
CYBER_INTENT_THRESHOLD = 0.53
CYBER_CONTEXT_PATTERN = re.compile(
    r"\b(?:account|access|api key|antivirus|computer system|credentials?|cyber|"
    r"computer|covert|dashboard|database|destructive|device|endpoint|email|files?|infrastructure|keylogger|laptop|login|malware|monitoring|network|phone|"
    r"one.time code|passcode|password|phish|portal|profile|ransomware|server|"
    r"records?|service|sign.in|spyware|token|tracking|tool|verification code|website|wireless|workstation)\b",
    re.IGNORECASE,
)


def training_paths() -> tuple[Path, ...]:
    regression_files = tuple(sorted(DATA_DIR.glob("cyber_intent_regression*.csv")))
    return TRAINING_FILES + regression_files


def _load_training_examples() -> tuple[list[str], list[int]]:
    prompts = []
    labels = []
    for dataset_path in training_paths():
        with dataset_path.open(newline="", encoding="utf-8") as dataset_file:
            reader = csv.DictReader(dataset_file)
            if not {"prompt", "label"}.issubset(reader.fieldnames or []):
                raise ValueError(f"{dataset_path} must contain prompt and label columns")
            for row in reader:
                prompt = row["prompt"].strip()
                label = int(row["label"])
                if not prompt or label not in {0, 1}:
                    raise ValueError(f"{dataset_path} contains an invalid training row")
                prompts.append(prompt)
                labels.append(label)

    if not prompts or set(labels) != {0, 1}:
        raise ValueError("Cyber-intent training data must contain both labels")
    return prompts, labels


@lru_cache(maxsize=1)
def _cyber_intent_model() -> Pipeline:
    prompts, labels = _load_training_examples()
    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 3),
            sublinear_tf=True,
        )),
        ("classifier", LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            C=1.0,
        )),
    ])
    model.fit(prompts, labels)
    return model


def is_cyber_abuse_intent(prompt: str) -> bool:
    if not CYBER_CONTEXT_PATTERN.search(prompt):
        return False
    probability = _cyber_intent_model().predict_proba([prompt])[0][1]
    return probability >= CYBER_INTENT_THRESHOLD
