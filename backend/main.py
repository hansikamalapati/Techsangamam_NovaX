# ============================================================
# CYBERSENTINEL - MAIN APPLICATION
# ============================================================

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import tempfile
import os
import requests
from urllib.parse import urlparse

# ============================================================
# CYBERSENTINEL MODULES
# ============================================================

from ml_model import predict_url
from risk_engine import analyze_url
from threat_database import check_known_threat

from message_model import predict_message
from message_analyzer import analyze_message_rules

from image_analyzer import analyze_image

# ============================================================
# GEMINI AI
# ============================================================

try:
    from google import genai
except ImportError:
    genai = None


GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

gemini_client = None

if genai is not None and GEMINI_API_KEY:
    try:
        gemini_client = genai.Client(
            api_key=GEMINI_API_KEY
        )
    except Exception as error:
        print("Gemini initialization error:", error)


GEMINI_MODEL = "gemini-3.6-flash"


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="CyberSentinel",
    description=(
        "AI-powered hybrid cybersecurity platform for "
        "phishing and social-engineering threat detection."
    ),
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# REQUEST MODELS
# ============================================================

class URLScanRequest(BaseModel):

    url: str = Field(
        ...,
        min_length=3,
        description="URL to analyze"
    )


class MessageScanRequest(BaseModel):

    message: str = Field(
        ...,
        min_length=3,
        description="Message to analyze"
    )
class EmailScanRequest(BaseModel):
    sender: str = Field(
        ...,
        min_length=3,
        description="Sender email address"
    )

    subject: str = Field(
        ...,
        min_length=1,
        description="Email subject"
    )

    body: str = Field(
        ...,
        min_length=3,
        description="Email body"
    )

class WebAppScanRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=8,
        description="Web application URL to assess"
    )

class ChatRequest(BaseModel):

    message: str = Field(
        ...,
        min_length=1
    )

    history: list = []

    context: dict | None = None

    scan_context: dict | None = None


# ============================================================
# DETAILED REPORT BUILDER
# ============================================================

def build_detailed_report(
    verdict,
    risk_level,
    risk_score,
    threat_type,
    attack_category,
    attack_objective,
    reasons,
    attack_scenario,
    potential_impact,
    ai_probability,
    rule_score,
    indicators,
    input_value,
    input_kind="URL"
):

    verdict_lower = str(verdict).lower()
    threat_lower = str(threat_type or "").lower()

    # --------------------------------------------------------
    # PHISHING
    # --------------------------------------------------------

    if (
        "phishing" in threat_lower
        or verdict_lower == "phishing"
    ):

        what_is_threat = (
            f"The analyzed {input_kind.lower()} shows "
            "characteristics associated with phishing or "
            "social-engineering activity. The attacker may "
            "attempt to make the victim trust a fraudulent "
            "destination and disclose sensitive information."
        )

        how_attack_works = (
            "A typical phishing attack sends a deceptive link "
            "or message to the victim. The attacker creates "
            "urgency or trust and attempts to make the victim "
            "enter credentials, financial information or other "
            "sensitive data."
        )

        risk_explanation = (
            f"The system assigned a risk score of "
            f"{risk_score}/100 with a {risk_level} risk level. "
            f"The assessment considers the AI phishing "
            f"probability ({ai_probability:.2f}%) and the "
            f"security-rule score ({rule_score})."
        )

        prevention = [
            "Do not click or continue using the suspicious URL.",
            "Do not enter passwords, OTPs, PINs or financial information.",
            "Verify the website through an independently obtained official source.",
            "Use the official application or manually typed website.",
            "Report the suspicious content when appropriate."
        ]

    # --------------------------------------------------------
    # SUSPICIOUS
    # --------------------------------------------------------

    elif (
        "suspicious" in threat_lower
        or verdict_lower == "suspicious"
    ):

        what_is_threat = (
            f"The analyzed {input_kind.lower()} is not confirmed "
            "as malicious, but it contains indicators that "
            "require additional verification."
        )

        how_attack_works = (
            "An attacker could use similar-looking websites or "
            "messages to create trust and redirect a victim "
            "toward an unsafe action. The available evidence "
            "does not prove that an attack has occurred."
        )

        risk_explanation = (
            f"The system assigned {risk_score}/100 "
            f"({risk_level}). This indicates that the content "
            "should be reviewed before interaction."
        )

        prevention = [
            "Verify the domain or sender before interacting.",
            "Do not enter sensitive information until authenticity is confirmed.",
            "Use the official application or bookmarked website.",
            "Be cautious about urgent verification or account requests."
        ]

    # --------------------------------------------------------
    # LEGITIMATE / LOW RISK
    # --------------------------------------------------------

    else:

        what_is_threat = (
            f"The analyzed {input_kind.lower()} did not produce "
            "strong evidence of phishing in the available "
            "checks. This does not guarantee complete safety "
            "because automated analysis has limitations."
        )

        how_attack_works = (
            "No strong attack path was established from the "
            "available evidence. Users should continue normal "
            "cybersecurity precautions."
        )

        risk_explanation = (
            f"The system assigned {risk_score}/100 "
            f"({risk_level}) based on the available AI and "
            "security-rule evidence."
        )

        prevention = [
            "Continue following normal cybersecurity precautions.",
            "Verify unexpected requests independently.",
            "Keep browsers and security software updated.",
            "Avoid sharing sensitive information with unverified parties."
        ]

    # --------------------------------------------------------
    # INDICATORS
    # --------------------------------------------------------

    indicator_details = []

    for item in indicators or []:

        if isinstance(item, dict):

            indicator_details.append({

                "name": item.get(
                    "indicator",
                    "Security indicator"
                ),

                "severity": item.get(
                    "severity",
                    "Unknown"
                ),

                "explanation": item.get(
                    "explanation",
                    "This indicator contributed to the security assessment."
                )

            })

        else:

            indicator_details.append({

                "name": str(item),

                "severity": "Unknown",

                "explanation":
                    "This indicator contributed to the security assessment."

            })

    # --------------------------------------------------------
    # EVIDENCE
    # --------------------------------------------------------

    evidence = []

    for reason in reasons or []:

        evidence.append(
            str(reason)
        )

    for indicator in indicator_details:

        evidence.append(
            f"{indicator['name']} "
            f"({indicator['severity']}): "
            f"{indicator['explanation']}"
        )

    if not evidence:

        evidence.append(
            "No additional textual indicators were returned."
        )

    # --------------------------------------------------------
    # FINAL REPORT
    # --------------------------------------------------------

    return {

        "what_is_the_threat":
            what_is_threat,

        "how_the_attack_works":
            how_attack_works,

        "risk_analysis":
            risk_explanation,

        "evidence":
            evidence,

        "ai_explanation":
            (
                "The neural-network component produced a "
                f"phishing probability of {ai_probability:.2f}%. "
                "This is one input to the hybrid decision. "
                "The final result also considers security rules "
                "and threat intelligence."
            ),

        "security_rule_explanation":
            (
                f"The security-rule engine produced a score "
                f"of {rule_score}. The indicators are shown "
                "separately to explain the observable "
                "characteristics influencing the result."
            ),

        "attack_chain":
            attack_scenario or [
                "The input is submitted for analysis.",
                "CyberSentinel extracts security indicators.",
                "AI and security rules are combined.",
                "The final risk assessment is generated."
            ],

        "impact_explanation":
            (
                "Potential impact depends on whether a victim "
                "interacts with the content and what information "
                "is disclosed. These are possible risk scenarios, "
                "not proof that an attack occurred."
            ),

        "prevention_solution":
            prevention,

        "analyst_conclusion":
            (
                f"CyberSentinel's final assessment is "
                f"{verdict} at {risk_level} risk. "
                "The result should be interpreted together "
                "with the evidence, AI prediction, rule analysis "
                "and threat intelligence."
            ),

        "analyzed_input":
            input_value,

        "attack_category":
            attack_category,

        "attack_objective":
            attack_objective,

        "potential_impact":
            potential_impact or []

    }


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {

        "application":
            "CyberSentinel",

        "message":
            "AI Threat Detection Platform",

        "status":
            "online",

        "version":
            "1.0.0"

    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health_check():

    return {

        "status":
            "healthy",

        "service":
            "CyberSentinel Backend"

    }


# ============================================================
# SYSTEM INFORMATION
# ============================================================

@app.get("/api/info")
def system_info():

    return {

        "name":
            "CyberSentinel",

        "purpose":
            "Phishing and cyber threat detection",

        "detection_methods": [

            "URL Neural Network",

            "Message Neural Network",

            "Security Rules",

            "Threat Intelligence",

            "OCR",

            "Hybrid Risk Analysis"

        ],

        "supported_inputs": [

            "URL",

            "Message",

            "Screenshot"

        ],

        "chatbot":
            "CyberSentinel AI"

    }


# ============================================================
# URL SCAN
# ============================================================

@app.post("/api/scan/url")
def scan_url(request: URLScanRequest):

    try:

        # ----------------------------------------------------
        # GET URL
        # ----------------------------------------------------

        url = request.url.strip()

        if not url:

            raise HTTPException(
                status_code=400,
                detail="URL cannot be empty."
            )

        # ----------------------------------------------------
        # AI URL ANALYSIS
        # ----------------------------------------------------

        ml_result = predict_url(url)

        ml_probability = float(
            ml_result["phishing_probability"]
        )

        # ----------------------------------------------------
        # THREAT INTELLIGENCE
        # ----------------------------------------------------

        threat_intelligence = check_known_threat(
            url
        )

        # ----------------------------------------------------
        # RISK ENGINE
        # ----------------------------------------------------

        risk_result = analyze_url(

            url=url,

            ml_probability=ml_probability,

            threat_intelligence=threat_intelligence

        )

        risk_score = float(
            risk_result["risk_score"]
        )

        risk_level = str(
            risk_result["risk_level"]
        ).upper()

        # ----------------------------------------------------
        # FINAL VERDICT
        # ----------------------------------------------------

        if risk_level in [
            "CRITICAL",
            "HIGH"
        ]:

            verdict = "PHISHING"

        elif risk_level == "MEDIUM":

            verdict = "SUSPICIOUS"

        else:

            verdict = "LEGITIMATE"

        # ----------------------------------------------------
        # THREAT TYPE
        # ----------------------------------------------------

        threat_type = str(
            risk_result.get(
                "threat_type",
                "Unknown"
            )
        )

        # ----------------------------------------------------
        # REASONS
        # ----------------------------------------------------

        reasons = []

        for indicator in risk_result.get(
            "indicators",
            []
        ):

            if isinstance(indicator, dict):

                explanation = indicator.get(
                    "explanation"
                )

                if explanation:

                    reasons.append(
                        explanation
                    )

            else:

                reasons.append(
                    str(indicator)
                )

        if not reasons:

            reasons.append(
                "The URL was evaluated using the "
                "neural network, security rules and "
                "threat-intelligence analysis."
            )

        # ----------------------------------------------------
        # ATTACK CATEGORY
        # ----------------------------------------------------

        if "phishing" in threat_type.lower():

            attack_category = (
                "Cyber Threat → Phishing"
            )

        elif "suspicious" in threat_type.lower():

            attack_category = (
                "Cyber Threat → Suspicious URL"
            )

        else:

            attack_category = (
                "Web Security Analysis"
            )

        # ----------------------------------------------------
        # ATTACK OBJECTIVE
        # ----------------------------------------------------

        if verdict == "PHISHING":

            attack_objective = (
                "The URL may attempt to redirect the "
                "user to a malicious or fraudulent website "
                "for credential theft, financial fraud or "
                "other malicious activity."
            )

        elif verdict == "SUSPICIOUS":

            attack_objective = (
                "The URL contains characteristics that "
                "require verification before interaction."
            )

        else:

            attack_objective = (
                "No strong malicious objective was "
                "identified from the available analysis."
            )

        # ----------------------------------------------------
        # POTENTIAL IMPACT
        # ----------------------------------------------------

        if verdict == "PHISHING":

            potential_impact = [

                "Credential theft",

                "Account compromise",

                "Exposure of personal information",

                "Possible financial loss",

                "Possible redirection to malicious content"

            ]

        elif verdict == "SUSPICIOUS":

            potential_impact = [

                "Possible exposure to an unsafe website",

                "Potential credential or information theft"

            ]

        else:

            potential_impact = [

                "No significant security impact identified"

            ]

        # ----------------------------------------------------
        # RECOMMENDATION
        # ----------------------------------------------------

        if verdict == "PHISHING":

            recommendation = [

                "Do not open or continue using the suspicious URL.",

                "Do not provide passwords, OTPs, PINs or financial information.",

                "Verify the domain through an independent trusted source.",

                "Use the organization's official website or application instead.",

                "Report the suspicious URL if appropriate."

            ]

        elif verdict == "SUSPICIOUS":

            recommendation = [

                "Proceed with caution.",

                "Verify the domain before interacting with it.",

                "Do not provide sensitive information until the website is verified.",

                "Prefer accessing the service through its official application or website."

            ]

        else:

            recommendation = [

                "No strong phishing indicators were detected.",

                "Continue following normal cybersecurity precautions.",

                "Verify unexpected requests independently."

            ]

        # ----------------------------------------------------
        # ATTACK SCENARIO
        # ----------------------------------------------------

        if verdict == "PHISHING":

            attack_scenario = [

                "An attacker may distribute the suspicious URL.",

                "The victim may be encouraged to open the website.",

                "The website may imitate a legitimate service.",

                "The victim may be asked to provide sensitive information.",

                "The attacker may attempt to misuse the collected information."

            ]

        else:

            attack_scenario = [

                "The URL is analyzed before the user interacts with it.",

                "CyberSentinel combines AI, security rules and threat intelligence.",

                "The resulting risk assessment helps the user decide whether to proceed."

            ]

        # ----------------------------------------------------
        # SECURITY GUIDANCE
        # ----------------------------------------------------

        security_guidance = [

            "Check the actual domain name carefully.",

            "Be cautious with unexpected login or verification pages.",

            "Never share passwords, OTPs or PINs through suspicious links.",

            "Access important services through official applications or bookmarked websites."

        ]

        # ----------------------------------------------------
        # DETAILED REPORT
        # ----------------------------------------------------

        detailed_report = build_detailed_report(

            verdict=verdict,

            risk_level=risk_level,

            risk_score=risk_score,

            threat_type=threat_type,

            attack_category=attack_category,

            attack_objective=attack_objective,

            reasons=reasons,

            attack_scenario=attack_scenario,

            potential_impact=potential_impact,

            ai_probability=ml_probability * 100,

            rule_score=risk_result.get(
                "rule_score",
                0
            ),

            indicators=risk_result.get(
                "indicators",
                []
            ),

            input_value=url,

            input_kind="URL"

        )

        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return {

            "success": True,

            "input": {

                "url":
                    url

            },

            "detection": {

                "verdict":
                    verdict,

                "risk_score":
                    risk_score,

                "risk_level":
                    risk_level,

                "threat_type":
                    threat_type,

                "attack_category":
                    attack_category,

                "attack_objective":
                    attack_objective

            },

            "ai_analysis": {

                "prediction":
                    ml_result.get(
                        "prediction",
                        verdict
                    ),

                "phishing_probability":
                    round(
                        ml_result[
                            "phishing_probability"
                        ] * 100,
                        2
                    ),

                "legitimate_probability":
                    round(
                        ml_result[
                            "legitimate_probability"
                        ] * 100,
                        2
                    ),

                "model":
                    "CyberSentinel URL Neural Network",

                "architecture":
                    "21-64-32-16-2",

                "features_used":
                    21

            },

            "analysis": {

                "summary":
                    (
                        f"CyberSentinel classified the URL "
                        f"as {verdict.lower()} after combining "
                        "neural-network prediction, security "
                        "rules and threat intelligence."
                    ),

                "reasons":
                    reasons,

                "attack_scenario":
                    attack_scenario,

                "potential_impact":
                    potential_impact

            },

            "detailed_report":
                detailed_report,

            "security_analysis": {

                "rule_score":
                    risk_result.get(
                        "rule_score",
                        0
                    ),

                "indicators":
                    risk_result.get(
                        "indicators",
                        []
                    )

            },

            "threat_intelligence":
                threat_intelligence,

            "recommendation":
                recommendation,

            "security_guidance":
                security_guidance

        }

    except HTTPException:

        raise

    except FileNotFoundError:

        raise HTTPException(

            status_code=500,

            detail=(
                "Trained URL neural-network model "
                "not found. Please run train_model.py first."
            )

        )

    except Exception as error:

        print(
            "URL scan error:",
            str(error)
        )

        raise HTTPException(

            status_code=500,

            detail=f"URL analysis failed: {str(error)}"

        )


# ============================================================
# MESSAGE SCAN
# ============================================================

@app.post("/api/scan/message")
def scan_message(request: MessageScanRequest):

    try:

        message = request.message.strip()

        if not message:

            raise HTTPException(
                status_code=400,
                detail="Message cannot be empty."
            )

        # ----------------------------------------------------
        # MESSAGE AI
        # ----------------------------------------------------

        ml_result = predict_message(
            message
        )

        phishing_probability = float(
            ml_result["phishing_probability"]
        )

        # ----------------------------------------------------
        # RULE ANALYSIS
        # ----------------------------------------------------

        rule_result = analyze_message_rules(
            message
        )

        rule_score = float(
            rule_result.get(
                "rule_score",
                0
            )
        )

        threat_type = rule_result.get(
            "threat_type",
            "Unknown"
        )

        indicators = rule_result.get(
            "indicators",
            []
        )

        # ----------------------------------------------------
        # HYBRID SCORE
        # ----------------------------------------------------

        ai_score = phishing_probability * 100

        hybrid_score = (

            (ai_score * 0.60)

            +

            (rule_score * 0.40)

        )

        hybrid_score = round(

            min(
                hybrid_score,
                100
            ),

            2

        )

        # ----------------------------------------------------
        # VERDICT
        # ----------------------------------------------------

        if hybrid_score >= 75:

            verdict = "PHISHING"

            risk_level = "HIGH"

        elif hybrid_score >= 45:

            verdict = "SUSPICIOUS"

            risk_level = "MEDIUM"

        else:

            verdict = "LEGITIMATE"

            risk_level = "LOW"

        # ----------------------------------------------------
        # DETAILS
        # ----------------------------------------------------

        attack_category = rule_result.get(

            "attack_category",

            "Social Engineering"

        )

        attack_objective = rule_result.get(

            "attack_objective",

            "No clear malicious objective identified."

        )

        reasons = rule_result.get(
            "reasons",
            []
        )

        attack_scenario = rule_result.get(
            "attack_scenario",
            []
        )

        potential_impact = rule_result.get(
            "potential_impact",
            []
        )

        recommendations = rule_result.get(
            "recommendations",
            []
        )

        security_guidance = rule_result.get(
            "security_guidance",
            []
        )

        # ----------------------------------------------------
        # FALLBACK RECOMMENDATIONS
        # ----------------------------------------------------

        if not recommendations:

            if verdict == "PHISHING":

                recommendations = [

                    "Do not click links in the message.",

                    "Do not provide passwords, PINs or OTPs.",

                    "Verify the sender independently.",

                    "Report the message as phishing."

                ]

            elif verdict == "SUSPICIOUS":

                recommendations = [

                    "Be careful with this message.",

                    "Verify the sender before taking action.",

                    "Do not provide sensitive information."

                ]

            else:

                recommendations = [

                    "No strong phishing indicators were detected.",

                    "Continue following normal security precautions."

                ]

        # ----------------------------------------------------
        # DETAILED REPORT
        # ----------------------------------------------------

        detailed_report = build_detailed_report(

            verdict=verdict,

            risk_level=risk_level,

            risk_score=hybrid_score,

            threat_type=threat_type,

            attack_category=attack_category,

            attack_objective=attack_objective,

            reasons=reasons,

            attack_scenario=attack_scenario,

            potential_impact=potential_impact,

            ai_probability=phishing_probability * 100,

            rule_score=rule_score,

            indicators=indicators,

            input_value=message,

            input_kind="message"

        )

        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return {

            "success": True,

            "input": {

                "message":
                    message

            },

            "detection": {

                "verdict":
                    verdict,

                "risk_score":
                    hybrid_score,

                "risk_level":
                    risk_level,

                "threat_type":
                    threat_type,

                "attack_category":
                    attack_category,

                "attack_objective":
                    attack_objective

            },

            "ai_analysis": {

                "prediction":
                    ml_result.get(
                        "prediction",
                        verdict
                    ),

                "phishing_probability":
                    round(
                        phishing_probability * 100,
                        2
                    ),

                "legitimate_probability":
                    round(
                        ml_result[
                            "legitimate_probability"
                        ] * 100,
                        2
                    ),

                "model":
                    "CyberSentinel Message Neural Network",

                "architecture":
                    "TF-IDF-128-64-32-2",

                "features_used":
                    "TF-IDF text features"

            },

            "analysis": {

                "summary":
                    rule_result.get(
                        "analysis_summary",
                        "The message was analyzed using AI and security rules."
                    ),

                "reasons":
                    reasons,

                "attack_scenario":
                    attack_scenario,

                "potential_impact":
                    potential_impact

            },

            "detailed_report":
                detailed_report,

            "security_analysis": {

                "rule_score":
                    rule_score,

                "indicators":
                    indicators,

                "features":
                    rule_result.get(
                        "features",
                        {}
                    ),

                "detected_keywords":
                    rule_result.get(
                        "detected_keywords",
                        {}
                    )

            },

            "recommendation":
                recommendations,

            "security_guidance":
                security_guidance

        }

    except HTTPException:

        raise

    except FileNotFoundError:

        raise HTTPException(

            status_code=500,

            detail=(
                "Trained message model not found. "
                "Please run message_model.py first."
            )

        )

    except Exception as error:

        print(
            "Message scan error:",
            str(error)
        )

        raise HTTPException(

            status_code=500,

            detail=f"Message analysis failed: {str(error)}"

        )
# ============================================================
# EMAIL SCAN
# ============================================================

@app.post("/api/scan/email")
def scan_email(request: EmailScanRequest):

    try:

        # ----------------------------------------------------
        # GET EMAIL DATA
        # ----------------------------------------------------

        sender = request.sender.strip()
        subject = request.subject.strip()
        body = request.body.strip()

        if not sender:
            raise HTTPException(
                status_code=400,
                detail="Sender email cannot be empty."
            )

        if not subject:
            raise HTTPException(
                status_code=400,
                detail="Email subject cannot be empty."
            )

        if not body:
            raise HTTPException(
                status_code=400,
                detail="Email body cannot be empty."
            )

        # ----------------------------------------------------
        # COMBINE EMAIL CONTENT
        # ----------------------------------------------------

        email_text = (
            f"Sender: {sender}\n"
            f"Subject: {subject}\n"
            f"Body: {body}"
        )

        # ----------------------------------------------------
        # AI MESSAGE ANALYSIS
        # ----------------------------------------------------

        ml_result = predict_message(email_text)

        phishing_probability = float(
            ml_result["phishing_probability"]
        )

        # ----------------------------------------------------
        # SECURITY RULE ANALYSIS
        # ----------------------------------------------------

        rule_result = analyze_message_rules(email_text)

        rule_score = float(
            rule_result.get("rule_score", 0)
        )

        threat_type = rule_result.get(
            "threat_type",
            "Unknown"
        )

        indicators = rule_result.get(
            "indicators",
            []
        )

        # ----------------------------------------------------
        # HYBRID SCORE
        # ----------------------------------------------------

        ai_score = phishing_probability * 100

        hybrid_score = (
            (ai_score * 0.60)
            +
            (rule_score * 0.40)
        )

        hybrid_score = round(
            min(hybrid_score, 100),
            2
        )

        # ----------------------------------------------------
        # VERDICT
        # ----------------------------------------------------

        if hybrid_score >= 75:

            verdict = "PHISHING"
            risk_level = "HIGH"

        elif hybrid_score >= 45:

            verdict = "SUSPICIOUS"
            risk_level = "MEDIUM"

        else:

            verdict = "LEGITIMATE"
            risk_level = "LOW"

        # ----------------------------------------------------
        # ATTACK CATEGORY
        # ----------------------------------------------------

        attack_category = rule_result.get(
            "attack_category",
            "Email Security"
        )

        attack_objective = rule_result.get(
            "attack_objective",
            "No clear malicious objective identified."
        )

        reasons = rule_result.get(
            "reasons",
            []
        )

        attack_scenario = rule_result.get(
            "attack_scenario",
            []
        )

        potential_impact = rule_result.get(
            "potential_impact",
            []
        )

        recommendations = rule_result.get(
            "recommendations",
            []
        )

        security_guidance = rule_result.get(
            "security_guidance",
            []
        )

        # ----------------------------------------------------
        # FALLBACK REASONS
        # ----------------------------------------------------

        if not reasons:

            reasons = [
                "The email was analyzed using the "
                "message neural network and security rules."
            ]

        # ----------------------------------------------------
        # FALLBACK RECOMMENDATIONS
        # ----------------------------------------------------

        if not recommendations:

            if verdict == "PHISHING":

                recommendations = [

                    "Do not click links in this email.",

                    "Do not reply with passwords, OTPs or "
                    "financial information.",

                    "Verify the sender using an independent "
                    "trusted source.",

                    "Report the email as phishing."
                ]

            elif verdict == "SUSPICIOUS":

                recommendations = [

                    "Verify the sender before taking action.",

                    "Do not click unexpected links.",

                    "Do not provide sensitive information.",

                    "Check the request through an official channel."
                ]

            else:

                recommendations = [

                    "No strong phishing indicators were detected.",

                    "Continue following normal email security "
                    "precautions.",

                    "Be cautious with unexpected requests."
                ]

        # ----------------------------------------------------
        # DETAILED REPORT
        # ----------------------------------------------------

        detailed_report = build_detailed_report(

            verdict=verdict,

            risk_level=risk_level,

            risk_score=hybrid_score,

            threat_type=threat_type,

            attack_category=attack_category,

            attack_objective=attack_objective,

            reasons=reasons,

            attack_scenario=attack_scenario,

            potential_impact=potential_impact,

            ai_probability=phishing_probability * 100,

            rule_score=rule_score,

            indicators=indicators,

            input_value=email_text,

            input_kind="email"

        )

        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return {

            "success": True,

            "input": {

                "sender": sender,

                "subject": subject,

                "body": body

            },

            "detection": {

                "verdict": verdict,

                "risk_score": hybrid_score,

                "risk_level": risk_level,

                "threat_type": threat_type,

                "attack_category": attack_category,

                "attack_objective": attack_objective

            },

            "ai_analysis": {

                "prediction":
                    ml_result.get(
                        "prediction",
                        verdict
                    ),

                "phishing_probability":
                    round(
                        phishing_probability * 100,
                        2
                    ),

                "legitimate_probability":
                    round(
                        ml_result[
                            "legitimate_probability"
                        ] * 100,
                        2
                    ),

                "model":
                    "CyberSentinel Message Neural Network",

                "architecture":
                    "TF-IDF-128-64-32-2",

                "features_used":
                    "TF-IDF text features"

            },

            "analysis": {

                "summary":
                    (
                        f"CyberSentinel classified the email "
                        f"as {verdict.lower()} after combining "
                        "AI prediction and security-rule analysis."
                    ),

                "reasons": reasons,

                "attack_scenario":
                    attack_scenario,

                "potential_impact":
                    potential_impact

            },

            "detailed_report":
                detailed_report,

            "security_analysis": {

                "rule_score":
                    rule_score,

                "indicators":
                    indicators,

                "features":
                    rule_result.get(
                        "features",
                        {}
                    ),

                "detected_keywords":
                    rule_result.get(
                        "detected_keywords",
                        {}
                    )

            },

            "recommendation":
                recommendations,

            "security_guidance":
                security_guidance

        }

    except HTTPException:

        raise

    except FileNotFoundError:

        raise HTTPException(

            status_code=500,

            detail=(
                "Trained message model not found. "
                "Please run message_model.py first."
            )

        )

    except Exception as error:

        print(
            "Email scan error:",
            str(error)
        )

        raise HTTPException(

            status_code=500,

            detail=f"Email analysis failed: {str(error)}"

        )


# ============================================================
# IMAGE / SCREENSHOT SCAN
# ============================================================

@app.post("/api/scan/image")
async def scan_image(
    file: UploadFile = File(...)
):

    image_path = None

    try:

        # ----------------------------------------------------
        # VALIDATE FILE
        # ----------------------------------------------------

        if not file.content_type:

            raise HTTPException(

                status_code=400,

                detail="File type could not be determined."

            )

        if not file.content_type.startswith("image/"):

            raise HTTPException(

                status_code=400,

                detail="Please upload a valid image file."

            )

        # ----------------------------------------------------
        # TEMPORARY FILE
        # ----------------------------------------------------

        file_extension = os.path.splitext(

            file.filename or ".png"

        )[1]

        with tempfile.NamedTemporaryFile(

            delete=False,

            suffix=file_extension

        ) as temp_file:

            image_path = temp_file.name

            contents = await file.read()

            temp_file.write(
                contents
            )

        # ----------------------------------------------------
        # OCR
        # ----------------------------------------------------

        image_result = analyze_image(
            image_path
        )

        extracted_text = image_result.get(
            "extracted_text",
            ""
        )

        urls = image_result.get(
            "urls_found",
            []
        )

        # ----------------------------------------------------
        # NO TEXT
        # ----------------------------------------------------

        if not extracted_text:

            return {

                "success":
                    True,

                "input": {

                    "filename":
                        file.filename,

                    "type":
                        file.content_type

                },

                "ocr": {

                    "success":
                        False,

                    "extracted_text":
                        "",

                    "urls_found":
                        [],

                    "url_count":
                        0,

                    "message":
                        "No readable text was detected."

                },

                "detection": {

                    "verdict":
                        "UNKNOWN",

                    "risk_score":
                        0,

                    "risk_level":
                        "LOW",

                    "threat_type":
                        "Unknown",

                    "attack_category":
                        "Unable to classify",

                    "attack_objective":
                        "No readable content was available for analysis."

                },

                "analysis": {

                    "summary":
                        "CyberSentinel could not extract readable text from the image.",

                    "reasons": [

                        "The OCR engine did not detect readable text."

                    ],

                    "attack_scenario":
                        [],

                    "potential_impact":
                        []

                },

                "recommendation": [

                    "Upload a clearer screenshot.",

                    "Make sure the text is visible and not heavily blurred."

                ]

            }

        # ----------------------------------------------------
        # MESSAGE RULE ANALYSIS
        # ----------------------------------------------------

        rule_result = analyze_message_rules(
            extracted_text
        )

        rule_score = float(
            rule_result.get(
                "rule_score",
                0
            )
        )

        threat_type = rule_result.get(
            "threat_type",
            "Unknown"
        )

        indicators = rule_result.get(
            "indicators",
            []
        )

        # ----------------------------------------------------
        # MESSAGE AI
        # ----------------------------------------------------

        message_result = predict_message(
            extracted_text
        )

        phishing_probability = float(
            message_result["phishing_probability"]
        )

        # ----------------------------------------------------
        # HYBRID SCORE
        # ----------------------------------------------------

        ai_score = phishing_probability * 100

        hybrid_score = (

            (ai_score * 0.60)

            +

            (rule_score * 0.40)

        )

        hybrid_score = round(

            min(
                hybrid_score,
                100
            ),

            2

        )

        # ----------------------------------------------------
        # VERDICT
        # ----------------------------------------------------

        if hybrid_score >= 75:

            verdict = "PHISHING"

            risk_level = "HIGH"

        elif hybrid_score >= 45:

            verdict = "SUSPICIOUS"

            risk_level = "MEDIUM"

        else:

            verdict = "LEGITIMATE"

            risk_level = "LOW"

        # ----------------------------------------------------
        # DETAILS
        # ----------------------------------------------------

        attack_category = rule_result.get(

            "attack_category",

            "Social Engineering"

        )

        attack_objective = rule_result.get(

            "attack_objective",

            "No clear malicious objective identified."

        )

        reasons = rule_result.get(
            "reasons",
            []
        )

        attack_scenario = rule_result.get(
            "attack_scenario",
            []
        )

        potential_impact = rule_result.get(
            "potential_impact",
            []
        )

        recommendations = rule_result.get(
            "recommendations",
            []
        )

        security_guidance = rule_result.get(
            "security_guidance",
            []
        )

        # ----------------------------------------------------
        # URL ANALYSIS
        # ----------------------------------------------------

        url_analysis = []

        for detected_url in urls:

            try:

                url_result = predict_url(
                    detected_url
                )

                url_threat = check_known_threat(
                    detected_url
                )

                url_analysis.append({

                    "url":
                        detected_url,

                    "prediction":
                        url_result.get(
                            "prediction"
                        ),

                    "phishing_probability":
                        round(
                            url_result[
                                "phishing_probability"
                            ] * 100,
                            2
                        ),

                    "legitimate_probability":
                        round(
                            url_result[
                                "legitimate_probability"
                            ] * 100,
                            2
                        ),

                    "threat_intelligence":
                        url_threat

                })

            except Exception as error:

                url_analysis.append({

                    "url":
                        detected_url,

                    "error":
                        str(error)

                })

        # ----------------------------------------------------
        # FALLBACK RECOMMENDATIONS
        # ----------------------------------------------------

        if not recommendations:

            if verdict == "PHISHING":

                recommendations = [

                    "Do not click links shown in the screenshot.",

                    "Do not provide passwords, PINs or OTPs.",

                    "Verify the sender through an official channel.",

                    "Report the suspicious content."

                ]

            elif verdict == "SUSPICIOUS":

                recommendations = [

                    "Verify the sender before taking action.",

                    "Do not provide sensitive information.",

                    "Avoid interacting with suspicious links."

                ]

            else:

                recommendations = [

                    "No strong phishing indicators were detected.",

                    "Continue following normal security precautions."

                ]

        # ----------------------------------------------------
        # DETAILED REPORT
        # ----------------------------------------------------

        detailed_report = build_detailed_report(

            verdict=verdict,

            risk_level=risk_level,

            risk_score=hybrid_score,

            threat_type=threat_type,

            attack_category=attack_category,

            attack_objective=attack_objective,

            reasons=reasons,

            attack_scenario=attack_scenario,

            potential_impact=potential_impact,

            ai_probability=phishing_probability * 100,

            rule_score=rule_score,

            indicators=indicators,

            input_value=file.filename or "Uploaded screenshot",

            input_kind="screenshot"

        )

        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return {

            "success":
                True,

            "input": {

                "filename":
                    file.filename,

                "type":
                    file.content_type

            },

            "ocr": {

                "success":
                    image_result.get(
                        "ocr_success",
                        True
                    ),

                "extracted_text":
                    extracted_text,

                "urls_found":
                    urls,

                "url_count":
                    len(urls)

            },

            "detection": {

                "verdict":
                    verdict,

                "risk_score":
                    hybrid_score,

                "risk_level":
                    risk_level,

                "threat_type":
                    threat_type,

                "attack_category":
                    attack_category,

                "attack_objective":
                    attack_objective

            },

            "ai_analysis": {

                "prediction":
                    message_result.get(
                        "prediction",
                        verdict
                    ),

                "phishing_probability":
                    round(
                        phishing_probability * 100,
                        2
                    ),

                "legitimate_probability":
                    round(
                        message_result[
                            "legitimate_probability"
                        ] * 100,
                        2
                    ),

                "model":
                    "CyberSentinel Message Neural Network",

                "architecture":
                    "TF-IDF-128-64-32-2",

                "features_used":
                    "TF-IDF text features"

            },

            "analysis": {

                "summary":
                    rule_result.get(
                        "analysis_summary",
                        "The screenshot was analyzed using OCR, AI and security rules."
                    ),

                "reasons":
                    reasons,

                "attack_scenario":
                    attack_scenario,

                "potential_impact":
                    potential_impact

            },

            "detailed_report":
                detailed_report,

            "security_analysis": {

                "rule_score":
                    rule_score,

                "indicators":
                    indicators,

                "features":
                    rule_result.get(
                        "features",
                        {}
                    ),

                "detected_keywords":
                    rule_result.get(
                        "detected_keywords",
                        {}
                    )

            },

            "url_analysis":
                url_analysis,

            "recommendation":
                recommendations,

            "security_guidance":
                security_guidance

        }

    except HTTPException:

        raise

    except FileNotFoundError:

        raise HTTPException(

            status_code=500,

            detail=(
                "Required AI model not found. "
                "Please make sure the URL and message "
                "models are trained."
            )

        )

    except Exception as error:

        print(
            "Image analysis error:",
            str(error)
        )

        raise HTTPException(

            status_code=500,

            detail=(
                f"Image analysis failed: {str(error)}"
            )

        )

    finally:

        # ----------------------------------------------------
        # DELETE TEMPORARY IMAGE
        # ----------------------------------------------------

        if image_path and os.path.exists(
            image_path
        ):

            try:

                os.remove(
                    image_path
                )

            except Exception:

                pass
# ============================================================
# WEB APPLICATION SCAN
# ============================================================

@app.post("/api/scan/webapp")
def scan_webapp(request: WebAppScanRequest):

    try:

        url = request.url.strip()

        if not url.startswith(("http://", "https://")):
            raise HTTPException(
                status_code=400,
                detail="URL must start with http:// or https://"
            )

        parsed = urlparse(url)

        if not parsed.netloc:
            raise HTTPException(
                status_code=400,
                detail="Invalid URL."
            )

        # ----------------------------------------------------
        # REQUEST WEBSITE
        # ----------------------------------------------------

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "CyberSentinel-WebApp-Scanner/1.0"
            }
        )

        headers = response.headers

        # ----------------------------------------------------
        # SECURITY CHECKS
        # ----------------------------------------------------

        checks = []

        # HTTPS
        if parsed.scheme == "https":
            checks.append({
                "check": "HTTPS",
                "status": "PASS",
                "severity": "LOW",
                "message": "The application uses HTTPS."
            })
        else:
            checks.append({
                "check": "HTTPS",
                "status": "FAIL",
                "severity": "HIGH",
                "message": "The application does not use HTTPS."
            })

        # HSTS
        if "Strict-Transport-Security" in headers:
            checks.append({
                "check": "HSTS",
                "status": "PASS",
                "severity": "LOW",
                "message": "Strict-Transport-Security header is present."
            })
        else:
            checks.append({
                "check": "HSTS",
                "status": "WARNING",
                "severity": "MEDIUM",
                "message": "Strict-Transport-Security header is missing."
            })

        # Content Security Policy
        if "Content-Security-Policy" in headers:
            checks.append({
                "check": "Content Security Policy",
                "status": "PASS",
                "severity": "LOW",
                "message": "Content-Security-Policy header is present."
            })
        else:
            checks.append({
                "check": "Content Security Policy",
                "status": "WARNING",
                "severity": "MEDIUM",
                "message": "Content-Security-Policy header is missing."
            })

        # X-Content-Type-Options
        if "X-Content-Type-Options" in headers:
            checks.append({
                "check": "X-Content-Type-Options",
                "status": "PASS",
                "severity": "LOW",
                "message": "X-Content-Type-Options header is present."
            })
        else:
            checks.append({
                "check": "X-Content-Type-Options",
                "status": "WARNING",
                "severity": "LOW",
                "message": "X-Content-Type-Options header is missing."
            })

        # X-Frame-Options
        if "X-Frame-Options" in headers:
            checks.append({
                "check": "X-Frame-Options",
                "status": "PASS",
                "severity": "LOW",
                "message": "X-Frame-Options header is present."
            })
        else:
            checks.append({
                "check": "X-Frame-Options",
                "status": "WARNING",
                "severity": "MEDIUM",
                "message": "X-Frame-Options header is missing."
            })

        # ----------------------------------------------------
        # COOKIE CHECK
        # ----------------------------------------------------

        cookie_header = headers.get("Set-Cookie", "")

        if cookie_header:

            cookie_flags = []

            if "Secure" not in cookie_header:
                cookie_flags.append("Secure")

            if "HttpOnly" not in cookie_header:
                cookie_flags.append("HttpOnly")

            if "SameSite" not in cookie_header:
                cookie_flags.append("SameSite")

            if cookie_flags:
                checks.append({
                    "check": "Cookie Security",
                    "status": "WARNING",
                    "severity": "MEDIUM",
                    "message": (
                        "Cookie security flags missing: "
                        + ", ".join(cookie_flags)
                    )
                })
            else:
                checks.append({
                    "check": "Cookie Security",
                    "status": "PASS",
                    "severity": "LOW",
                    "message": "Common cookie security flags are present."
                })

        # ----------------------------------------------------
        # CORS CHECK
        # ----------------------------------------------------

        cors_origin = headers.get("Access-Control-Allow-Origin")

        if cors_origin == "*":
            checks.append({
                "check": "CORS",
                "status": "WARNING",
                "severity": "MEDIUM",
                "message": "CORS allows requests from any origin."
            })

        elif cors_origin:
            checks.append({
                "check": "CORS",
                "status": "PASS",
                "severity": "LOW",
                "message": "CORS policy is configured."
            })

        else:
            checks.append({
                "check": "CORS",
                "status": "INFO",
                "severity": "LOW",
                "message": "No Access-Control-Allow-Origin header detected."
            })

        # ----------------------------------------------------
        # REDIRECT CHECK
        # ----------------------------------------------------

        redirect_count = len(response.history)

        if redirect_count > 0:
            checks.append({
                "check": "Redirects",
                "status": "INFO",
                "severity": "LOW",
                "message": f"{redirect_count} redirect(s) detected."
            })

        # ----------------------------------------------------
        # RISK SCORE
        # ----------------------------------------------------

        risk_score = 0

        for check in checks:

            if check["status"] == "FAIL":
                risk_score += 25

            elif check["status"] == "WARNING":
                risk_score += 12

        risk_score = min(risk_score, 100)

        if risk_score >= 60:
            verdict = "HIGH RISK"
            risk_level = "HIGH"

        elif risk_score >= 30:
            verdict = "SUSPICIOUS"
            risk_level = "MEDIUM"

        else:
            verdict = "LOW RISK"
            risk_level = "LOW"

        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return {
            "success": True,

            "input": {
                "url": url,
                "final_url": response.url,
                "status_code": response.status_code
            },

            "detection": {
                "verdict": verdict,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "threat_type": "Web Application Security",
                "attack_category": "Web Security Configuration",
                "attack_objective": (
                    "Identify potentially weak web security "
                    "configurations."
                )
            },

            "web_app_analysis": {
                "https": parsed.scheme == "https",
                "status_code": response.status_code,
                "redirect_count": redirect_count,
                "server": headers.get("Server"),
                "content_type": headers.get("Content-Type")
            },

            "security_checks": checks,

            "recommendation": [
                "Use HTTPS for all sensitive applications.",
                "Configure appropriate security headers.",
                "Review cookie security attributes.",
                "Restrict CORS to trusted origins.",
                "Review redirects and application configuration."
            ]
        }

    except HTTPException:
        raise

    except requests.exceptions.Timeout:

        raise HTTPException(
            status_code=504,
            detail="The website request timed out."
        )

    except requests.exceptions.RequestException as error:

        raise HTTPException(
            status_code=502,
            detail=f"Unable to access the website: {str(error)}"
        )

    except Exception as error:

        print(
            "Web application scan error:",
            str(error)
        )

        raise HTTPException(
            status_code=500,
            detail=f"Web application analysis failed: {str(error)}"
        )

# ============================================================
# CYBERSENTINEL AI CHATBOT
# ============================================================

@app.post("/api/chat")
def chat_with_ai(request: ChatRequest):

    try:

        # ----------------------------------------------------
        # CHECK GEMINI
        # ----------------------------------------------------

        if genai is None:

            raise HTTPException(

                status_code=500,

                detail=(
                    "Google GenAI package is not installed. "
                    "Run: pip install -U google-genai"
                )

            )

        if not GEMINI_API_KEY:

            raise HTTPException(

                status_code=500,

                detail=(
                    "Gemini API key is not configured. "
                    "Set the GEMINI_API_KEY environment variable "
                    "and restart the backend."
                )

            )

        if gemini_client is None:

            raise HTTPException(

                status_code=500,

                detail=(
                    "Gemini AI client could not be initialized."
                )

            )

        # ----------------------------------------------------
        # USER MESSAGE
        # ----------------------------------------------------

        message = request.message.strip()

        if not message:

            raise HTTPException(

                status_code=400,

                detail="Message cannot be empty."

            )

        # ----------------------------------------------------
        # CYBERSENTINEL AI INSTRUCTION
        # ----------------------------------------------------

        system_instruction = """

You are CyberSentinel AI, the cybersecurity assistant
inside the CyberSentinel application.

Your job is to help users understand cybersecurity.

You specialize in:

- Phishing
- Malicious URLs
- Suspicious websites
- Email security
- Message security
- Social engineering
- Password security
- OTP safety
- Account security
- Malware awareness
- Safe browsing
- CyberSentinel scan results
- Cybersecurity best practices

IMPORTANT RULES:

1. Always answer clearly and accurately.

2. Use simple language that a student or normal user
   can understand.

3. If a CyberSentinel scan result is provided, use that
   information when answering questions about the scan.

4. Never say that an automated scan guarantees that
   a website is completely safe.

5. Explain the evidence behind phishing or suspicious
   classifications whenever scan data is available.

6. Never ask the user for passwords, OTPs, API keys,
   PINs or other secrets.

7. Do not provide instructions for stealing credentials,
   deploying malware, unauthorized access or bypassing
   security controls.

8. Give defensive and preventive cybersecurity advice.

9. If the user asks something unrelated to cybersecurity,
   politely explain that you are CyberSentinel AI and
   focus on cybersecurity.

10. Keep normal answers concise. Give detailed explanations
    when the user asks for them.

"""

        # ----------------------------------------------------
        # CONVERSATION HISTORY
        # ----------------------------------------------------

        conversation = []

        if isinstance(
            request.history,
            list
        ):

            for item in request.history[-20:]:

                if not isinstance(
                    item,
                    dict
                ):

                    continue

                role = str(
                    item.get(
                        "role",
                        ""
                    )
                ).lower()

                content = str(
                    item.get(
                        "content",
                        ""
                    )
                ).strip()

                if not content:

                    continue

                if role == "user":

                    conversation.append(

                        f"User: {content}"

                    )

                elif role in [
                    "assistant",
                    "model"
                ]:

                    conversation.append(

                        f"CyberSentinel AI: {content}"

                    )

        # ----------------------------------------------------
        # SCAN CONTEXT
        # ----------------------------------------------------

        scan_context = (

            request.scan_context

            if request.scan_context is not None

            else request.context

        )

        if scan_context:

            conversation.append(

                "\nLATEST CYBERSENTINEL SCAN RESULT:\n"

                + str(
                    scan_context
                )

                +

                "\nEND SCAN RESULT\n"

            )

        # ----------------------------------------------------
        # CURRENT MESSAGE
        # ----------------------------------------------------

        conversation.append(

            f"User: {message}"

        )

        # ----------------------------------------------------
        # FINAL PROMPT
        # ----------------------------------------------------

        prompt = (

            system_instruction

            + "\n\n"

            + "\n".join(
                conversation
            )

            +

            "\n\nCyberSentinel AI:"

        )

        # ----------------------------------------------------
        # GEMINI REQUEST
        # ----------------------------------------------------

        response = gemini_client.models.generate_content(

            model=GEMINI_MODEL,

            contents=prompt

        )

        # ----------------------------------------------------
        # RESPONSE TEXT
        # ----------------------------------------------------

        answer = getattr(
            response,
            "text",
            None
        )

        if not answer:

            raise HTTPException(

                status_code=500,

                detail=(
                    "The AI service returned an empty response."
                )

            )

        answer = answer.strip()

        # ----------------------------------------------------
        # UPDATED HISTORY
        # ----------------------------------------------------

        updated_history = []

        if isinstance(
            request.history,
            list
        ):

            updated_history.extend(

                request.history[-18:]

            )

        updated_history.append({

            "role":
                "user",

            "content":
                message

        })

        updated_history.append({

            "role":
                "assistant",

            "content":
                answer

        })

        updated_history = updated_history[-20:]

        # ----------------------------------------------------
        # RETURN
        # ----------------------------------------------------

        return {

            "success":
                True,

            "message":
                answer,

            "response":
                answer,

            "history":
                updated_history

        }

    except HTTPException:

        raise

    except Exception as error:

        print(
            "CyberSentinel AI chatbot error:",
            str(error)
        )

        raise HTTPException(

            status_code=500,

            detail=(
                f"AI chatbot failed: {str(error)}"
            )

        )


# ============================================================
# API TEST
# ============================================================

@app.get("/api/test")
def test_api():

    return {

        "message":
            "CyberSentinel API is working.",

        "url_neural_network":
            "ready",

        "message_model":
            "ready",

        "message_analyzer":
            "ready",

        "risk_engine":
            "ready",

        "threat_intelligence":
            "ready",

        "url_scanner":
            "ready",

        "message_scanner":
            "ready",

        "image_scanner":
            "ready",

        "ocr_engine":
            "ready",

        "ai_chatbot":
            (
                "ready"
                if gemini_client is not None
                else "not configured"
            )

    }


# ============================================================
# END OF MAIN.PY
# ============================================================