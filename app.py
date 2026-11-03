
import streamlit as st

from src.detector import detect_prompt
from src.threat_analyzer import analyze_threat


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
    "Enter a prompt to analyze it using independent "
    "prompt injection and cyber threat detection layers."
)

st.divider()

prompt = st.text_area(
    "Enter your prompt",
    placeholder="Example: Ignore all previous instructions...",
    height=150
)



def evaluate_security(prompt):

    # Layer 1: Hybrid prompt injection detector
    injection_result = detect_prompt(prompt)

    # Layer 2: Cyber threat analyzer
    threat_result = analyze_threat(prompt)

    categories = set(
        injection_result.get("detected_categories", [])
    )

    # Only strong, explicit injection indicators
    # should trigger an injection-based BLOCK.
    high_confidence_injection = {
        "instruction_override",
        "prompt_extraction",
        "jailbreak",
        "data_exfiltration",
    }

    confirmed_injection = bool(
        categories.intersection(high_confidence_injection)
    )

    # Aggregate decisions
    if threat_result["decision"] == "BLOCK":
        final_decision = "BLOCK"

    elif confirmed_injection:
        final_decision = "BLOCK"

    elif (
        threat_result["decision"] == "REVIEW"
        or injection_result["status"] == "SUSPICIOUS"
    ):
        final_decision = "REVIEW"

    else:
        final_decision = "ALLOW"

    return {
        "final_decision": final_decision,
        "injection": injection_result,
        "cyber_threat": threat_result
    }


if st.button("Analyze Security", type="primary"):

    if not prompt.strip():
        st.warning("Please enter a prompt.")

    else:

        results = evaluate_security(prompt)

        injection = results["injection"]
        cyber = results["cyber_threat"]
        decision = results["final_decision"]

        st.divider()
        st.subheader("Overall Security Decision")

        if decision == "BLOCK":
            st.error("🚨 BLOCK — Strong threat indicators detected.")

        elif decision == "REVIEW":
            st.warning("⚠️ REVIEW — Additional context is required.")

        else:
            st.success("✅ ALLOW — No known threat indicators detected.")

        # Display individual detection layers
        st.subheader("Detection Layer Results")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### Prompt Injection")

            st.metric(
                "Detection status",
                injection["status"]
            )

            st.metric(
                "ML malicious probability",
                f'{injection["ml_probability"] * 100:.1f}%'
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

        st.divider()

        st.subheader("Technical Analysis")

        with st.expander("View complete detection results"):
            st.json(results)

st.divider()

st.caption(
    "AI Security Project | Multi-Layer Threat Detection Prototype"
)
