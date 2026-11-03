
import streamlit as st

from src.openai_adapter import model_adapter_from_environment
from src.secure_model import secure_generate


st.set_page_config(
    page_title="AI Security Center",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI Security Center")

st.markdown(
    "### Multi-Layer Prompt Injection and Cyber Threat Detection"
)

st.info(
    "Analyze the request separately from external text. External content is "
    "untrusted data and is never merged into the user request. An optional "
    "model response is generated only after the security gateway allows it."
)

st.divider()

with st.form("source_aware_security_analysis"):
    user_request = st.text_area(
        "Trusted user request",
        placeholder="Example: Summarize the following webpage.",
        height=120,
        key="trusted_user_request",
    )
    external_content = st.text_area(
        "Untrusted external content (optional)",
        placeholder="Paste webpage, document, or other external text here.",
        height=180,
        key="untrusted_external_content",
    )
    submitted = st.form_submit_button("Analyze security", type="primary")


if submitted:

    if not user_request.strip():
        st.warning("Please enter a trusted user request.")

    else:

        model_configuration_failed = False
        try:
            model = model_adapter_from_environment()
        except Exception:
            model = None
            model_configuration_failed = True

        gateway_result = secure_generate(
            user_request,
            external_content,
            model=model,
        )
        results = gateway_result["security"]

        decision = results["final_decision"]

        st.divider()
        st.subheader("Overall Security Decision")

        if decision == "BLOCK":
            st.error("🚨 BLOCK — Strong threat indicators detected; nothing was sent.")

        elif decision == "REVIEW":
            st.warning("⚠️ REVIEW — Additional context is required.")
            st.caption("Quarantined for manual review; no content is forwarded.")

        else:
            st.success("✅ ALLOW — No known threat indicators detected.")
            if model_configuration_failed:
                st.error("Model configuration is unavailable; no request was sent.")
            elif gateway_result["model_status"] == "not_configured":
                st.info(
                    "No model provider is configured; no request was sent. "
                    "Check MODEL_PROVIDER and its credentials, endpoint, and model settings."
                )
            elif gateway_result["model_status"] == "responded":
                st.subheader("Model response")
                st.write(gateway_result["model_response"])
            elif gateway_result["model_status"] == "model_error":
                st.error("The model adapter failed; no response was produced.")

        st.subheader("Trusted user request")
        request_analysis = results["trusted_request_analysis"]
        injection = request_analysis["injection"]
        cyber = request_analysis["cyber_threat"]

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### Prompt Injection")
            probability = injection["ml_probability"]

            st.metric(
                "Detection status",
                injection["status"]
            )

            st.metric(
                "ML malicious probability",
                f"{probability * 100:.1f}%" if probability is not None else "Unavailable"
            )

            st.write(
                "Rule detected:",
                injection["rule_detected"]
            )

            st.write(
                "Categories:",
                injection["detected_categories"]
                or "None"
            )

        with col2:
            st.markdown("#### Cyber Threat Analysis")

            st.metric(
                "Detection decision",
                cyber["decision"]
            )

            st.write(
                "Threat categories:",
                cyber["cyber_categories"]
                or "None"
            )

            st.write(
                "Injection categories:",
                cyber["injection_categories"]
                or "None"
            )

            st.write(
                "Reason:",
                cyber["reason"]
            )

        external_analysis = results["untrusted_external_content_analysis"]
        if external_analysis is not None:
            st.subheader("Untrusted external content")
            st.caption("Analyzed as data; it is not merged into the trusted request.")
            if results["external_content_quarantined"]:
                st.warning("External content is quarantined for manual review.")
            ext_col1, ext_col2 = st.columns(2)

            with ext_col1:
                st.metric(
                    "Prompt-injection status",
                    external_analysis["injection"]["status"],
                )
                st.write(
                    "Injection categories:",
                    external_analysis["injection"]["detected_categories"] or "None",
                )

            with ext_col2:
                st.metric(
                    "Cyber threat decision",
                    external_analysis["cyber_threat"]["decision"],
                )
                st.write(
                    "Reason:",
                    external_analysis["cyber_threat"]["reason"],
                )

        st.subheader("Technical Analysis")

        with st.expander("View complete detection results"):
            st.json({
                "security": results,
                "model_status": gateway_result["model_status"],
                "forwarded_to_model": gateway_result["forwarded_to_model"],
            })

st.divider()

st.caption(
    "AI Security Project | Multi-Layer Threat Detection Prototype"
)
