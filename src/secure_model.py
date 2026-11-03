import logging
from dataclasses import dataclass
from typing import Protocol

from src.security import can_forward_to_model, evaluate_security


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ModelInput:
    trusted_user_request: str
    untrusted_external_content: str


class ModelAdapter(Protocol):
    def generate(self, model_input: ModelInput) -> str:
        """Generate a response while preserving source trust labels."""


def _unavailable_source(error: Exception) -> dict:
    reason = "Security analysis failed; manual review required."
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


def _security_failure(
    error: Exception,
    trusted_user_request: str,
    untrusted_external_content: str,
) -> dict:
    logger.error(
        "Secure model gateway rejected request because security analysis failed "
        "(error_type=%s)",
        type(error).__name__,
    )
    request_result = _unavailable_source(error)
    external_result = (
        _unavailable_source(error)
        if untrusted_external_content.strip()
        else None
    )
    return {
        "final_decision": "REVIEW",
        "injection": request_result["injection"],
        "cyber_threat": request_result["cyber_threat"],
        "trusted_request_analysis": request_result,
        "untrusted_external_content_analysis": external_result,
        "external_content_quarantined": external_result is not None,
        "source_context": {
            "trusted_user_request": {
                "trust": "trusted",
                "text": trusted_user_request,
            },
            "untrusted_external_content": {
                "trust": "untrusted",
                "text": untrusted_external_content,
            },
        },
        "analysis_available": False,
        "quarantined": True,
        "forwarding_allowed": False,
        "forwarded_to_model": False,
    }


def secure_generate(
    trusted_user_request: str,
    untrusted_external_content: str = "",
    model: ModelAdapter | None = None,
) -> dict:
    try:
        security_result = evaluate_security(
            trusted_user_request,
            untrusted_external_content,
        )
    except Exception as error:
        security_result = _security_failure(
            error,
            trusted_user_request,
            untrusted_external_content,
        )

    result = {
        "security": security_result,
        "final_decision": security_result.get("final_decision", "REVIEW"),
        "model_status": "quarantined",
        "model_response": None,
        "forwarded_to_model": False,
    }

    if not can_forward_to_model(security_result):
        return result

    if model is None:
        result["model_status"] = "not_configured"
        return result

    model_input = ModelInput(
        trusted_user_request=trusted_user_request,
        untrusted_external_content=untrusted_external_content,
    )
    try:
        response = model.generate(model_input)
    except Exception as error:
        logger.error(
            "Secure model adapter failed (error_type=%s)",
            type(error).__name__,
        )
        result["model_status"] = "model_error"
        result["forwarded_to_model"] = True
        result["model_error_type"] = type(error).__name__
        return result

    result["model_status"] = "responded"
    result["model_response"] = response
    result["forwarded_to_model"] = True
    return result