import logging

from src.detector import detect_prompt
from src.threat_analyzer import analyze_threat

logger = logging.getLogger(__name__)


HIGH_CONFIDENCE_INJECTION = {
    "instruction_override",
    "prompt_extraction",
    "jailbreak",
    "encoded_instruction",
    "data_exfiltration",
}


def build_source_context(user_request: str, external_content: str) -> dict:
    return {
        "trusted_user_request": {
            "trust": "trusted",
            "text": user_request,
        },
        "untrusted_external_content": {
            "trust": "untrusted",
            "text": external_content,
        },
    }


def _failed_source_result(source_name: str, error: Exception) -> dict:
    logger.error(
        "Security analysis failed for source=%s error_type=%s",
        source_name,
        type(error).__name__,
    )
    reason = "Analysis unavailable; manual review required."
    return {
        "final_decision": "REVIEW",
        "injection": {
            "status": "UNAVAILABLE",
            "risk_score": 0,
            "detected_categories": ["analysis_unavailable"],
            "ml_probability": None,
            "model_available": False,
            "rule_detected": False,
            "message": reason,
        },
        "cyber_threat": {
            "decision": "REVIEW",
            "injection_categories": [],
            "cyber_categories": [],
            "reason": reason,
        },
        "analysis_available": False,
        "error_type": type(error).__name__,
    }


def _evaluate_source(text: str, source_name: str) -> dict:
    try:
        injection_result = detect_prompt(text)
        threat_result = analyze_threat(text)
    except Exception as error:
        return _failed_source_result(source_name, error)

    categories = set(injection_result.get("detected_categories", []))

    if threat_result["decision"] == "BLOCK":
        decision = "BLOCK"
    elif categories.intersection(HIGH_CONFIDENCE_INJECTION):
        decision = "BLOCK"
    elif (
        threat_result["decision"] == "REVIEW"
        or injection_result["status"] == "SUSPICIOUS"
    ):
        decision = "REVIEW"
    else:
        decision = "ALLOW"

    return {
        "final_decision": decision,
        "injection": injection_result,
        "cyber_threat": threat_result,
        "analysis_available": bool(injection_result.get("model_available", True)),
    }


def evaluate_security(prompt: str, external_content: str = "") -> dict:
    user_request = prompt if isinstance(prompt, str) else ""
    external_text = external_content if isinstance(external_content, str) else ""
    source_context = build_source_context(user_request, external_text)
    try:
        if not user_request.strip():
            request_result = _failed_source_result(
                "trusted_user_request",
                ValueError("request must be non-empty text"),
            )
        else:
            request_result = _evaluate_source(
                source_context["trusted_user_request"]["text"],
                "trusted_user_request",
            )

        external_result = None
        if external_content is not None and not isinstance(external_content, str):
            external_result = _failed_source_result(
                "untrusted_external_content",
                TypeError("external content must be text"),
            )
        elif external_text.strip():
            external_result = _evaluate_source(
                external_text,
                "untrusted_external_content",
            )

        if request_result["final_decision"] == "BLOCK":
            final_decision = "BLOCK"
        elif external_result and external_result["final_decision"] != "ALLOW":
            final_decision = "REVIEW"
        else:
            final_decision = request_result["final_decision"]
    except Exception as error:
        request_result = _failed_source_result("security_boundary", error)
        external_result = None
        if external_text.strip():
            external_result = _failed_source_result("security_boundary_external", error)
        final_decision = "REVIEW"

    analysis_available = bool(request_result.get("analysis_available", False))
    if external_result is not None:
        analysis_available = analysis_available and bool(
            external_result.get("analysis_available", False)
        )
    quarantined = final_decision != "ALLOW" or not analysis_available
    forwarding_allowed = final_decision == "ALLOW" and analysis_available
    logger.info(
        "Security evaluation completed decision=%s request_decision=%s "
        "external_content_present=%s external_decision=%s analysis_available=%s "
        "quarantined=%s forwarding_allowed=%s",
        final_decision,
        request_result["final_decision"],
        external_result is not None,
        external_result["final_decision"] if external_result else "NOT_PROVIDED",
        analysis_available,
        quarantined,
        forwarding_allowed,
    )

    return {
        "final_decision": final_decision,
        "injection": request_result["injection"],
        "cyber_threat": request_result["cyber_threat"],
        "trusted_request_analysis": request_result,
        "untrusted_external_content_analysis": external_result,
        "external_content_quarantined": bool(
            external_result
            and external_result["final_decision"] != "ALLOW"
        ),
        "source_context": source_context,
        "quarantined": quarantined,
        "analysis_available": analysis_available,
        "forwarding_allowed": forwarding_allowed,
        "forwarded_to_model": False,
    }


def can_forward_to_model(security_result: dict) -> bool:
    return (
        security_result.get("forwarding_allowed") is True
        and security_result.get("final_decision") == "ALLOW"
        and security_result.get("quarantined") is False
    )