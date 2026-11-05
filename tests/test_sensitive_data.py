from src.sensitive_data import find_sensitive_data, redact_sensitive_data


def test_finds_common_pii_without_returning_values():
    text = (
        "Email jane.doe@example.com, phone (415) 555-0132, "
        "SSN 123-45-6789, card 4111 1111 1111 1111."
    )

    findings = find_sensitive_data(text)

    assert {finding["category"] for finding in findings} == {
        "email",
        "phone",
        "ssn",
        "payment_card",
    }
    assert all("value" not in finding for finding in findings)


def test_finds_common_secrets_and_private_keys():
    text = (
        'api_key="sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789" '
        "AWS AKIAIOSFODNN7EXAMPLE"
    )

    findings = find_sensitive_data(text)

    assert "api_key" in {finding["category"] for finding in findings}
    assert "aws_access_key" in {finding["category"] for finding in findings}


def test_redacts_sensitive_values_but_preserves_surrounding_text():
    redacted, categories = redact_sensitive_data(
        "Contact jane.doe@example.com for help."
    )

    assert redacted == "Contact [REDACTED_EMAIL] for help."
    assert categories == ["email"]
    assert "jane.doe@example.com" not in redacted


def test_detects_exact_and_formatted_synthetic_canaries():
    canary = "SYNTHETIC_CANARY_" + "A1" * 24

    assert find_sensitive_data(f"leaked: {canary}", canary)[0]["category"] == (
        "synthetic_canary"
    )
    assert find_sensitive_data(f"leaked: {canary}")[0]["category"] == (
        "synthetic_canary"
    )


def test_leaves_non_sensitive_text_unchanged():
    text = "The office closes at five."

    assert redact_sensitive_data(text) == (text, [])