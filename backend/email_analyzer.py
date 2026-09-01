# ============================================================
# CYBERSENTINEL - EMAIL SECURITY ANALYZER
# ============================================================

import re
from urllib.parse import urlparse


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE
)


URGENT_WORDS = [
    "urgent",
    "immediately",
    "act now",
    "verify now",
    "within 24 hours",
    "account suspended",
    "account locked",
    "final warning",
    "security alert"
]


CREDENTIAL_WORDS = [
    "password",
    "otp",
    "one time password",
    "pin",
    "login",
    "verify your account",
    "bank details",
    "credit card",
    "debit card"
]


def extract_urls(text):

    return URL_PATTERN.findall(
        text or ""
    )


def analyze_email(
    sender="",
    subject="",
    body=""
):

    findings = []

    combined = " ".join([
        sender or "",
        subject or "",
        body or ""
    ]).lower()

    # --------------------------------------------------------
    # Urgency
    # --------------------------------------------------------

    urgent_matches = [
        word
        for word in URGENT_WORDS
        if word in combined
    ]

    if urgent_matches:

        findings.append({
            "indicator": "Urgency",
            "severity": "MEDIUM",
            "details": urgent_matches
        })

    # --------------------------------------------------------
    # Credential requests
    # --------------------------------------------------------

    credential_matches = [
        word
        for word in CREDENTIAL_WORDS
        if word in combined
    ]

    if credential_matches:

        findings.append({
            "indicator": "Credential Request",
            "severity": "HIGH",
            "details": credential_matches
        })

    # --------------------------------------------------------
    # Suspicious sender
    # --------------------------------------------------------

    if sender:

        sender_domain = ""

        if "@" in sender:

            sender_domain = (
                sender.split("@")[-1]
                .strip()
                .lower()
            )

        if sender_domain:

            if sender_domain.endswith(
                ".invalid"
            ):

                findings.append({
                    "indicator":
                        "Invalid Sender Domain",
                    "severity":
                        "HIGH",
                    "details":
                        sender_domain
                })

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    urls = extract_urls(
        body
    )

    if urls:

        findings.append({
            "indicator": "Embedded URLs",
            "severity": "MEDIUM",
            "details": urls
        })

        for url in urls:

            parsed = urlparse(url)

            if parsed.scheme != "https":

                findings.append({
                    "indicator":
                        "Non-HTTPS URL",
                    "severity":
                        "MEDIUM",
                    "details":
                        url
                })

    # --------------------------------------------------------
    # Score
    # --------------------------------------------------------

    score = 0

    severity_weights = {
        "LOW": 5,
        "MEDIUM": 15,
        "HIGH": 25,
        "CRITICAL": 35
    }

    for finding in findings:

        score += severity_weights.get(
            finding["severity"],
            5
        )

    score = min(
        score,
        100
    )

    if score >= 65:
        verdict = "PHISHING"
        level = "HIGH"

    elif score >= 35:
        verdict = "SUSPICIOUS"
        level = "MEDIUM"

    else:
        verdict = "LEGITIMATE"
        level = "LOW"

    return {

        "verdict": verdict,

        "risk_level": level,

        "rule_score": score,

        "indicators": findings,

        "urls_found": urls,

        "summary": (
            "Email analyzed for phishing language, "
            "credential requests, embedded URLs and "
            "sender-related indicators."
        )
    }