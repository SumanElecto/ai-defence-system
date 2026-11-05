import re


CANARY_PATTERN = re.compile(r"\bSYNTHETIC_CANARY_[A-F0-9]{48}\b")
_EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)
_PHONE_PATTERN = re.compile(
    r"(?<!\w)(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?!\w)"
)
_SSN_PATTERN = re.compile(
    r"\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"
)
_CARD_CANDIDATE_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----[\s\S]+?-----END \1-----"
)
_SECRET_PATTERNS = (
    (
        "api_key",
        re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b"),
        0,
    ),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), 0),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), 0),
    (
        "bearer_token",
        re.compile(r"\bBearer\s+([A-Za-z0-9._~+/-]{16,}={0,2})", re.IGNORECASE),
        1,
    ),
    ("private_key", _PRIVATE_KEY_PATTERN, 0),
    (
        "credential_assignment",
        re.compile(
            r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
            r"password|passwd|secret|token)\b\s*[:=]\s*[\"']?"
            r"([A-Za-z0-9_./+=-]{12,})",
            re.IGNORECASE,
        ),
        1,
    ),
)


def _passes_luhn(value: str) -> bool:
    digits = [int(character) for character in value if character.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False

    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def find_sensitive_data(text: str, canary: str | None = None) -> list[dict]:
    if not isinstance(text, str) or not text:
        return []

    matches = []

    def add_matches(category: str, pattern: re.Pattern, group: int = 0) -> None:
        for match in pattern.finditer(text):
            start, end = match.span(group)
            if end > start:
                matches.append({"category": category, "start": start, "end": end})

    add_matches("email", _EMAIL_PATTERN)
    add_matches("phone", _PHONE_PATTERN)
    add_matches("ssn", _SSN_PATTERN)
    add_matches("private_key", _PRIVATE_KEY_PATTERN)

    for match in _CARD_CANDIDATE_PATTERN.finditer(text):
        if _passes_luhn(match.group()):
            matches.append({
                "category": "payment_card",
                "start": match.start(),
                "end": match.end(),
            })

    for category, pattern, group in _SECRET_PATTERNS:
        if category != "private_key":
            add_matches(category, pattern, group)

    for match in CANARY_PATTERN.finditer(text):
        matches.append({
            "category": "synthetic_canary",
            "start": match.start(),
            "end": match.end(),
        })

    if canary and canary not in CANARY_PATTERN.pattern:
        start = 0
        while (index := text.find(canary, start)) != -1:
            matches.append({
                "category": "synthetic_canary",
                "start": index,
                "end": index + len(canary),
            })
            start = index + len(canary)

    matches.sort(key=lambda finding: (
        finding["start"],
        -(finding["end"] - finding["start"]),
    ))
    non_overlapping = []
    previous_end = -1
    for finding in matches:
        if finding["start"] >= previous_end:
            non_overlapping.append(finding)
            previous_end = finding["end"]
    return non_overlapping


def redact_sensitive_data(
    text: str,
    canary: str | None = None,
) -> tuple[str, list[str]]:
    findings = find_sensitive_data(text, canary)
    if not findings:
        return text, []

    redacted = []
    categories = []
    cursor = 0
    for finding in findings:
        redacted.append(text[cursor:finding["start"]])
        category = finding["category"]
        redacted.append(f"[REDACTED_{category.upper()}]")
        cursor = finding["end"]
        if category not in categories:
            categories.append(category)
    redacted.append(text[cursor:])
    return "".join(redacted), categories