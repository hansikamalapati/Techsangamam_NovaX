# ============================================================
# CYBERSENTINEL - HYBRID AI RISK ENGINE
# ============================================================
#
# Combines:
#   1. Machine Learning prediction
#   2. URL security rules
#   3. Domain analysis
#   4. Typosquatting detection
#   5. Threat intelligence
#
# HTTPS is NOT treated as proof of legitimacy.
# An unknown URL is NOT automatically considered safe.
#
# ============================================================

import re
import ipaddress
from urllib.parse import urlparse

import tldextract


# ============================================================
# CONFIGURATION
# ============================================================

SUSPICIOUS_KEYWORDS = {
    "login": "Login activity detected.",
    "signin": "Sign-in activity detected.",
    "sign-in": "Sign-in activity detected.",
    "verify": "Verification activity detected.",
    "verification": "Verification activity detected.",
    "authenticate": "Authentication activity detected.",
    "authentication": "Authentication activity detected.",
    "account": "Account-related activity detected.",
    "password": "Password-related activity detected.",
    "credential": "Credential-related activity detected.",
    "bank": "Banking-related activity detected.",
    "banking": "Banking-related activity detected.",
    "payment": "Payment-related activity detected.",
    "wallet": "Wallet-related activity detected.",
    "otp": "OTP-related activity detected.",
    "refund": "Refund-related activity detected.",
    "prize": "Prize-related activity detected.",
    "winner": "Winner-related activity detected.",
    "bonus": "Bonus-related activity detected.",
    "claim": "Claim-related activity detected.",
    "suspended": "Account suspension language detected.",
    "suspension": "Account suspension language detected.",
    "unlock": "Account-unlock language detected.",
    "recover": "Account recovery language detected.",
    "recovery": "Account recovery language detected.",
    "billing": "Billing-related activity detected.",
    "invoice": "Invoice-related activity detected.",
}


HIGH_RISK_KEYWORDS = {
    "password",
    "credential",
    "otp",
    "wallet",
    "verify",
    "verification",
    "authenticate",
    "authentication",
    "suspended",
    "suspension",
    "unlock",
}


SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".buzz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
}


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(url: str) -> str:

    if not isinstance(url, str):
        return ""

    url = url.strip()

    if not url:
        return ""

    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    return url


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain_parts(url: str):

    normalized = normalize_url(url)

    try:
        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return "", "", "", ""

    try:
        extracted = tldextract.extract(normalized)

        domain = (extracted.domain or "").lower()
        suffix = (extracted.suffix or "").lower()
        subdomain = (extracted.subdomain or "").lower()

    except Exception:
        domain = ""
        suffix = ""
        subdomain = ""

    return hostname, domain, suffix, subdomain


# ============================================================
# DOMAIN STRUCTURE ANALYSIS
# ============================================================

def analyze_domain_structure(url: str):

    indicators = []

    normalized = normalize_url(url)

    if not normalized:
        return indicators

    try:
        parsed = urlparse(normalized)
    except Exception:
        return indicators

    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return indicators

    _, domain, suffix, subdomain = extract_domain_parts(
        normalized
    )

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    try:

        ip = ipaddress.ip_address(hostname)

        if ip.is_private:

            indicators.append({
                "indicator": "IP address used as hostname",
                "explanation": (
                    "The URL uses a private IP address "
                    "instead of a conventional domain."
                ),
                "severity": "HIGH",
                "weight": 30,
            })

        else:

            indicators.append({
                "indicator": "IP address used as hostname",
                "explanation": (
                    "The destination uses a numeric IP address "
                    "instead of a conventional domain."
                ),
                "severity": "HIGH",
                "weight": 30,
            })

    except ValueError:
        pass

    # --------------------------------------------------------
    # SUBDOMAIN DEPTH
    # --------------------------------------------------------

    subdomain_parts = [
        x for x in subdomain.split(".")
        if x
    ]

    if len(subdomain_parts) >= 4:

        indicators.append({
            "indicator": "Excessive subdomains",
            "explanation": (
                "Several nested subdomains may obscure "
                "the actual registered domain."
            ),
            "severity": "HIGH",
            "weight": 18,
        })

    elif len(subdomain_parts) >= 3:

        indicators.append({
            "indicator": "Multiple subdomains",
            "explanation": (
                "The hostname contains multiple nested "
                "subdomains."
            ),
            "severity": "MEDIUM",
            "weight": 10,
        })

    # --------------------------------------------------------
    # LONG DOMAIN
    # --------------------------------------------------------

    if len(domain) >= 35:

        indicators.append({
            "indicator": "Very long registered domain",
            "explanation": (
                "The registered domain is unusually long "
                "and may indicate deceptive naming."
            ),
            "severity": "MEDIUM",
            "weight": 10,
        })

    # --------------------------------------------------------
    # HYPHENS
    # --------------------------------------------------------

    hyphen_count = domain.count("-")

    if hyphen_count >= 5:

        indicators.append({
            "indicator": "Excessive domain hyphens",
            "explanation": (
                "The registered domain contains many hyphens."
            ),
            "severity": "HIGH",
            "weight": 15,
        })

    elif hyphen_count >= 3:

        indicators.append({
            "indicator": "Multiple domain hyphens",
            "explanation": (
                "The registered domain contains several hyphens."
            ),
            "severity": "MEDIUM",
            "weight": 7,
        })

    # --------------------------------------------------------
    # DIGITS
    # --------------------------------------------------------

    digit_count = sum(
        character.isdigit()
        for character in domain
    )

    if digit_count >= 4:

        indicators.append({
            "indicator": "Many digits in domain",
            "explanation": (
                "The registered domain contains several "
                "numeric characters."
            ),
            "severity": "MEDIUM",
            "weight": 10,
        })

    # --------------------------------------------------------
    # MIXED ALPHANUMERIC DOMAIN
    # --------------------------------------------------------

    if (
        any(c.isalpha() for c in domain)
        and
        any(c.isdigit() for c in domain)
    ):

        indicators.append({
            "indicator": "Mixed alphanumeric domain",
            "explanation": (
                "The domain mixes alphabetic and numeric "
                "characters, which can be used for "
                "look-alike domains."
            ),
            "severity": "MEDIUM",
            "weight": 7,
        })

    # --------------------------------------------------------
    # PUNYCODE
    # --------------------------------------------------------

    if "xn--" in hostname:

        indicators.append({
            "indicator": "Punycode domain",
            "explanation": (
                "The hostname contains Punycode and should "
                "be examined for look-alike behavior."
            ),
            "severity": "MEDIUM",
            "weight": 12,
        })

    # --------------------------------------------------------
    # SUSPICIOUS TLD
    # --------------------------------------------------------

    hostname_with_dot = "." + hostname

    for tld in SUSPICIOUS_TLDS:

        if hostname_with_dot.endswith(tld):

            indicators.append({
                "indicator": "Suspicious top-level domain",
                "explanation": (
                    f"The domain uses the {tld} TLD. "
                    "Some phishing campaigns use inexpensive "
                    "or disposable domains."
                ),
                "severity": "MEDIUM",
                "weight": 10,
            })

            break

    # --------------------------------------------------------
    # LONG SUBDOMAIN
    # --------------------------------------------------------

    if len(subdomain) >= 30:

        indicators.append({
            "indicator": "Long subdomain",
            "explanation": (
                "The subdomain is unusually long and may "
                "be used to hide the actual destination."
            ),
            "severity": "MEDIUM",
            "weight": 10,
        })

    return indicators


# ============================================================
# URL SECURITY RULES
# ============================================================

def analyze_url_rules(url: str):

    normalized = normalize_url(url)

    if not normalized:

        return (
            100,
            [{
                "indicator": "Invalid URL",
                "explanation": (
                    "The submitted URL is invalid."
                ),
                "severity": "HIGH",
                "weight": 100,
            }]
        )

    try:
        parsed = urlparse(normalized)
    except Exception:

        return (
            100,
            [{
                "indicator": "Malformed URL",
                "explanation": (
                    "The URL could not be parsed."
                ),
                "severity": "HIGH",
                "weight": 100,
            }]
        )

    hostname = (parsed.hostname or "").lower()

    if not hostname:

        return (
            100,
            [{
                "indicator": "Missing hostname",
                "explanation": (
                    "The URL does not contain a valid hostname."
                ),
                "severity": "HIGH",
                "weight": 100,
            }]
        )

    score = 0
    indicators = []

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    if parsed.scheme.lower() == "http":

        score += 8

        indicators.append({
            "indicator": "No HTTPS",
            "explanation": (
                "The URL does not use HTTPS. "
                "This increases risk but does not prove phishing."
            ),
            "severity": "LOW",
            "weight": 8,
        })

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    elif parsed.scheme.lower() == "https":

        # IMPORTANT:
        # This is INFORMATIONAL only.
        # It must never make the URL suspicious.

        indicators.append({
            "indicator": "HTTPS enabled",
            "explanation": (
                "HTTPS encrypts communication but does not "
                "prove that the website is legitimate."
            ),
            "severity": "INFO",
            "weight": 0,
        })

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    try:

        ipaddress.ip_address(hostname)

        score += 30

        indicators.append({
            "indicator": "IP address used as hostname",
            "explanation": (
                "The destination uses an IP address instead "
                "of a conventional domain."
            ),
            "severity": "HIGH",
            "weight": 30,
        })

    except ValueError:
        pass

    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if "@" in normalized:

        score += 25

        indicators.append({
            "indicator": "@ symbol in URL",
            "explanation": (
                "The @ symbol can be abused to disguise "
                "the actual destination."
            ),
            "severity": "HIGH",
            "weight": 25,
        })

    # --------------------------------------------------------
    # EMBEDDED CREDENTIALS
    # --------------------------------------------------------

    if parsed.username or parsed.password:

        score += 20

        indicators.append({
            "indicator": "Embedded URL credentials",
            "explanation": (
                "The URL contains user-information syntax "
                "before the hostname."
            ),
            "severity": "HIGH",
            "weight": 20,
        })

    # --------------------------------------------------------
    # PORT
    # --------------------------------------------------------

    try:

        port = parsed.port

        if port is not None:

            if port not in {
                80,
                443,
                8080,
                8443
            }:

                score += 12

                indicators.append({
                    "indicator": "Non-standard port",
                    "explanation": (
                        f"The URL uses port {port}, which is "
                        "unusual for normal public websites."
                    ),
                    "severity": "MEDIUM",
                    "weight": 12,
                })

    except ValueError:

        score += 20

        indicators.append({
            "indicator": "Invalid port",
            "explanation": (
                "The URL contains an invalid port."
            ),
            "severity": "HIGH",
            "weight": 20,
        })

    # --------------------------------------------------------
    # DOUBLE SLASH
    # --------------------------------------------------------

    path = parsed.path or ""

    if "//" in path:

        score += 8

        indicators.append({
            "indicator": "Obfuscated URL path",
            "explanation": (
                "Repeated slashes in the path may indicate "
                "redirection or URL obfuscation."
            ),
            "severity": "MEDIUM",
            "weight": 8,
        })

    # --------------------------------------------------------
    # FRAGMENT
    # --------------------------------------------------------

    if parsed.fragment and len(parsed.fragment) > 80:

        score += 5

        indicators.append({
            "indicator": "Large URL fragment",
            "explanation": (
                "The URL contains an unusually large "
                "fragment section."
            ),
            "severity": "LOW",
            "weight": 5,
        })

    # --------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    searchable_text = " ".join([
        hostname,
        parsed.path or "",
        parsed.query or "",
        parsed.fragment or "",
    ]).lower()

    tokens = set(
        token
        for token in re.split(
            r"[^a-zA-Z0-9]+",
            searchable_text
        )
        if token
    )

    detected_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword.lower() in tokens:
            detected_keywords.append(keyword)

    if detected_keywords:

        normal_keywords = [
            x for x in detected_keywords
            if x not in HIGH_RISK_KEYWORDS
        ]

        high_keywords = [
            x for x in detected_keywords
            if x in HIGH_RISK_KEYWORDS
        ]

        keyword_score = (
            min(len(normal_keywords) * 4, 12)
            +
            min(len(high_keywords) * 8, 24)
        )

        score += keyword_score

        severity = (
            "HIGH"
            if len(high_keywords) >= 2
            else "MEDIUM"
        )

        indicators.append({
            "indicator": "Suspicious security keywords",
            "explanation": (
                "Detected security-related terms: "
                +
                ", ".join(detected_keywords)
                +
                ". These may be associated with "
                "credential collection, verification "
                "or financial activity."
            ),
            "severity": severity,
            "weight": keyword_score,
        })

    # --------------------------------------------------------
    # LONG URL
    # --------------------------------------------------------

    if len(normalized) > 250:

        score += 18

        indicators.append({
            "indicator": "Extremely long URL",
            "explanation": (
                "The URL is unusually long and may contain "
                "obfuscation or excessive parameters."
            ),
            "severity": "HIGH",
            "weight": 18,
        })

    elif len(normalized) > 150:

        score += 10

        indicators.append({
            "indicator": "Long URL",
            "explanation": (
                "The URL is longer than typical website addresses."
            ),
            "severity": "MEDIUM",
            "weight": 10,
        })

    # --------------------------------------------------------
    # QUERY PARAMETERS
    # --------------------------------------------------------

    query = parsed.query or ""

    if query:

        parameters = [
            item
            for item in query.split("&")
            if item
        ]

        if len(parameters) >= 10:

            score += 12

            indicators.append({
                "indicator": "Many URL parameters",
                "explanation": (
                    "The URL contains many query parameters."
                ),
                "severity": "MEDIUM",
                "weight": 12,
            })

    # --------------------------------------------------------
    # URL ENCODING
    # --------------------------------------------------------

    encoded_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            normalized
        )
    )

    if encoded_count >= 5:

        score += 12

        indicators.append({
            "indicator": "Heavy URL encoding",
            "explanation": (
                "The URL contains many percent-encoded "
                "characters that may be used for obfuscation."
            ),
            "severity": "MEDIUM",
            "weight": 12,
        })

    # --------------------------------------------------------
    # DOMAIN STRUCTURE
    # --------------------------------------------------------

    structural_indicators = (
        analyze_domain_structure(normalized)
    )

    existing_indicators = {
        item.get("indicator")
        for item in indicators
    }

    for item in structural_indicators:

        indicator_name = item.get(
            "indicator"
        )

        if indicator_name not in existing_indicators:

            indicators.append(item)

            score += float(
                item.get("weight", 0)
            )

    return min(
        int(round(score)),
        100
    ), indicators


# ============================================================
# SAFE SCORE
# ============================================================

def _safe_score(value):

    try:
        value = float(value)
    except Exception:
        return 0.0

    return max(
        0.0,
        min(value, 100.0)
    )


# ============================================================
# GET SCORE FROM ANALYSIS
# ============================================================

def _get_analysis_score(analysis):

    if not isinstance(analysis, dict):
        return 0.0

    for key in [
        "risk_score",
        "score",
        "threat_score",
        "security_score",
        "domain_score",
        "signal_score",
        "domain_signal_score",
        "security_signal_score",
        "domain_risk_score",
    ]:

        if key in analysis:

            return _safe_score(
                analysis.get(key)
            )

    return 0.0


# ============================================================
# TYPOSQUATTING SCORE
# ============================================================

def _get_typo_score(typo):

    if not isinstance(typo, dict):
        return 0.0

    # Direct score
    for key in [
        "risk_score",
        "score",
        "typosquatting_score",
    ]:

        if key in typo:

            score = _safe_score(
                typo.get(key)
            )

            if score > 0:
                return score

    # Similarity
    similarity = typo.get(
        "similarity",
        typo.get(
            "similarity_percent",
            0
        )
    )

    try:
        similarity = float(similarity)
    except Exception:
        similarity = 0.0

    if similarity > 1:
        similarity /= 100.0

    similarity = max(
        0.0,
        min(similarity, 1.0)
    )

    detected = bool(
        typo.get(
            "detected",
            False
        )
    )

    if detected:

        if similarity >= 0.90:
            return 85.0

        if similarity >= 0.80:
            return 75.0

        if similarity >= 0.70:
            return 65.0

        return 55.0

    return similarity * 40.0


# ============================================================
# THREAT CLASSIFICATION
# ============================================================

def classify_threat(
    url: str,
    indicators: list,
    typosquatting: dict = None
):

    url_text = (url or "").lower()

    if typosquatting is None:
        typosquatting = {}

    # --------------------------------------------------------
    # TYPOSQUATTING
    # --------------------------------------------------------

    if bool(
        typosquatting.get(
            "detected",
            False
        )
    ):

        brand = (
            typosquatting.get("brand")
            or
            typosquatting.get("closest_brand")
        )

        if brand:

            return (
                "Brand Impersonation / "
                f"Typosquatting ({brand})"
            )

        return "Brand Impersonation / Typosquatting"

    # --------------------------------------------------------
    # CREDENTIAL PHISHING
    # --------------------------------------------------------

    credential_words = [
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "password",
        "credential",
        "authenticate",
        "authentication",
        "account",
        "otp",
        "unlock",
        "recover",
    ]

    if any(
        word in url_text
        for word in credential_words
    ):

        return "Credential Phishing"

    # --------------------------------------------------------
    # FINANCIAL PHISHING
    # --------------------------------------------------------

    financial_words = [
        "bank",
        "banking",
        "payment",
        "wallet",
        "refund",
        "billing",
        "invoice",
    ]

    if any(
        word in url_text
        for word in financial_words
    ):

        return "Financial Phishing"

    # --------------------------------------------------------
    # REWARD SCAM
    # --------------------------------------------------------

    reward_words = [
        "prize",
        "winner",
        "bonus",
        "reward",
        "claim",
    ]

    if any(
        word in url_text
        for word in reward_words
    ):

        return "Prize / Reward Scam"

    # --------------------------------------------------------
    # STRUCTURAL MANIPULATION
    # --------------------------------------------------------

    manipulation_indicators = {
        "IP address used as hostname",
        "@ symbol in URL",
        "Embedded URL credentials",
        "Excessive domain hyphens",
        "Very long registered domain",
        "Extremely long URL",
        "Punycode domain",
        "Excessive subdomains",
        "Non-standard port",
        "Heavy URL encoding",
        "Obfuscated URL path",
    }

    if any(
        item.get("indicator")
        in manipulation_indicators
        for item in indicators
    ):

        return "Suspicious URL Manipulation"

    # ========================================================
    # IMPORTANT FIX
    # ========================================================
    #
    # INFO indicators such as:
    #
    #   HTTPS enabled
    #
    # do NOT make a URL suspicious.
    #
    # Only LOW / MEDIUM / HIGH security indicators count.
    #
    # ========================================================

    security_indicators = [
        item
        for item in indicators
        if str(
            item.get(
                "severity",
                ""
            )
        ).upper()
        in {
            "LOW",
            "MEDIUM",
            "HIGH",
        }
    ]

    if security_indicators:

        return "Suspicious URL"

    return "No Significant Threat Detected"


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(risk_score):

    score = float(risk_score)

    if score >= 85:
        return "CRITICAL"

    if score >= 65:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


# ============================================================
# RECOMMENDATION
# ============================================================

def generate_recommendation(
    risk_level,
    threat_type
):

    if risk_level == "CRITICAL":

        return (
            "Do not open or interact with this URL. "
            "Do not enter passwords, OTPs, payment information "
            "or other sensitive data. Access the service through "
            "its independently verified official website."
        )

    if risk_level == "HIGH":

        return (
            "Avoid interacting with this URL. "
            "Verify the domain independently and use the "
            "organization's official website or application."
        )

    if risk_level == "MEDIUM":

        return (
            "Exercise caution. Multiple security indicators "
            "were detected. Verify the domain, sender and "
            "context before interacting."
        )

    return (
        "No significant phishing indicators were detected "
        "by the current analysis. This does not guarantee "
        "that the website is safe."
    )


# ============================================================
# ATTACK OBJECTIVE
# ============================================================

def generate_attack_objective(threat_type):

    if "Typosquatting" in threat_type:

        return (
            "The suspected objective is brand impersonation. "
            "The attacker may use a look-alike domain to "
            "deceive users into trusting the destination."
        )

    if threat_type == "Credential Phishing":

        return (
            "The suspected objective is credential harvesting. "
            "An attacker may attempt to collect usernames, "
            "passwords or authentication information."
        )

    if threat_type == "Financial Phishing":

        return (
            "The suspected objective is financial information "
            "theft or fraudulent payment activity."
        )

    if threat_type == "Prize / Reward Scam":

        return (
            "The suspected objective is to exploit a reward "
            "or prize theme to obtain personal or financial "
            "information."
        )

    if threat_type == "Suspicious URL Manipulation":

        return (
            "The URL contains structural characteristics "
            "that may disguise the actual destination."
        )

    if threat_type == "Suspicious URL":

        return (
            "The URL contains characteristics that require "
            "additional verification."
        )

    return (
        "No specific attack objective was identified from "
        "the available URL evidence."
    )


# ============================================================
# ATTACK SCENARIO
# ============================================================

def generate_attack_scenario(threat_type):

    if "Typosquatting" in threat_type:

        return [
            "The attacker registers a domain that resembles a trusted brand.",
            "The look-alike domain may be distributed through messages or other channels.",
            "The victim may mistake the domain for the genuine service.",
            "The victim may then be directed to a fraudulent page.",
            "The attacker may attempt to collect sensitive information.",
        ]

    if threat_type == "Credential Phishing":

        return [
            "The attacker distributes a deceptive URL.",
            "The victim is persuaded to believe the request is legitimate.",
            "The victim is directed to an authentication or verification page.",
            "The attacker may request usernames, passwords or authentication information.",
            "Captured information could potentially be used for account compromise.",
        ]

    if threat_type == "Financial Phishing":

        return [
            "The attacker distributes a fraudulent banking or payment URL.",
            "The victim is persuaded that an account or payment action is required.",
            "The victim may be asked for financial information.",
            "The collected information could potentially be used for fraud.",
        ]

    if threat_type == "Prize / Reward Scam":

        return [
            "The attacker presents a fake prize, reward or bonus.",
            "The victim is encouraged to follow the URL.",
            "The attacker may request personal or financial information.",
            "The information could potentially be abused for fraud.",
        ]

    return [
        "The URL is submitted to CyberSentinel.",
        "URL security characteristics are extracted.",
        "The machine-learning model generates a probability.",
        "Domain and structural signals are evaluated.",
        "Threat-intelligence sources are checked when available.",
        "Typosquatting and brand-impersonation signals are evaluated.",
        "All evidence is combined by the hybrid risk engine.",
        "The final risk assessment determines the recommended action.",
    ]


# ============================================================
# POTENTIAL IMPACT
# ============================================================

def generate_potential_impact(
    threat_type,
    risk_level
):

    impacts = []

    if "Typosquatting" in threat_type:

        impacts.extend([
            "Brand impersonation",
            "Credential theft",
            "Account compromise",
            "Social-engineering exploitation",
        ])

    elif threat_type == "Credential Phishing":

        impacts.extend([
            "Credential theft",
            "Account compromise",
            "Unauthorized account access",
            "Identity abuse",
        ])

    elif threat_type == "Financial Phishing":

        impacts.extend([
            "Financial information theft",
            "Unauthorized transactions",
            "Payment fraud",
            "Identity abuse",
        ])

    elif threat_type == "Prize / Reward Scam":

        impacts.extend([
            "Personal information exposure",
            "Financial fraud",
            "Identity theft",
            "Social-engineering exploitation",
        ])

    else:

        impacts.extend([
            "Exposure to an unsafe website",
            "Potential information theft",
            "Social-engineering risk",
        ])

    if risk_level in {
        "HIGH",
        "CRITICAL",
    }:

        impacts.append(
            "Potential compromise of sensitive information"
        )

    return impacts


# ============================================================
# HYBRID RISK CALCULATION
# ============================================================

def calculate_hybrid_risk(
    ml_probability,
    threat_intelligence,
    rule_score,
    indicators=None,
    domain_analysis=None,
    typosquatting=None,
):

    if indicators is None:
        indicators = []

    if domain_analysis is None:
        domain_analysis = {}

    if typosquatting is None:
        typosquatting = {}

    if not isinstance(
        threat_intelligence,
        dict
    ):
        threat_intelligence = {}

    # --------------------------------------------------------
    # ML
    # --------------------------------------------------------

    try:
        ml_probability = float(
            ml_probability
        )
    except Exception:
        ml_probability = 0.5

    ml_probability = max(
        0.0,
        min(
            ml_probability,
            1.0
        )
    )

    ml_score = (
        ml_probability * 100.0
    )

    # --------------------------------------------------------
    # RULES
    # --------------------------------------------------------

    rule_score = _safe_score(
        rule_score
    )

    # --------------------------------------------------------
    # THREAT INTELLIGENCE
    # --------------------------------------------------------

    threat_matched = bool(
        threat_intelligence.get(
            "matched",
            threat_intelligence.get(
                "known_threat",
                False
            )
        )
    )

    if threat_matched:

        threat_score = 100.0

    else:

        threat_score = _get_analysis_score(
            threat_intelligence
        )

    # --------------------------------------------------------
    # DOMAIN
    # --------------------------------------------------------

    domain_score = _get_analysis_score(
        domain_analysis
    )

    if domain_score == 0:

        domain_indicators = (
            domain_analysis.get(
                "indicators",
                []
            )
        )

        if isinstance(
            domain_indicators,
            list
        ):

            for item in domain_indicators:

                severity = str(
                    item.get(
                        "severity",
                        ""
                    )
                ).upper()

                if severity == "HIGH":
                    domain_score += 25

                elif severity == "MEDIUM":
                    domain_score += 12

                elif severity == "LOW":
                    domain_score += 5

    domain_score = min(
        domain_score,
        100.0
    )

    # --------------------------------------------------------
    # TYPOSQUATTING
    # --------------------------------------------------------

    typo_score = _get_typo_score(
        typosquatting
    )

    typo_detected = bool(
        typosquatting.get(
            "detected",
            False
        )
    )

    # --------------------------------------------------------
    # INDICATOR COUNTS
    # --------------------------------------------------------

    high_count = 0
    medium_count = 0
    low_count = 0

    for indicator in indicators:

        severity = str(
            indicator.get(
                "severity",
                ""
            )
        ).upper()

        if severity == "HIGH":
            high_count += 1

        elif severity == "MEDIUM":
            medium_count += 1

        elif severity == "LOW":
            low_count += 1

    # --------------------------------------------------------
    # EVIDENCE FUSION
    # --------------------------------------------------------

    risk_score = (

        ml_score * 0.30

        +

        rule_score * 0.25

        +

        domain_score * 0.20

        +

        typo_score * 0.15

        +

        threat_score * 0.10

    )

    # ========================================================
    # STRONG EVIDENCE OVERRIDES
    # ========================================================

    # Known threat
    if threat_matched:

        risk_score = max(
            risk_score,
            95
        )

    # Confirmed typosquatting
    if typo_detected:

        risk_score = max(
            risk_score,
            75
        )

        similarity = typosquatting.get(
            "similarity",
            typosquatting.get(
                "similarity_percent",
                0
            )
        )

        try:
            similarity = float(
                similarity
            )
        except Exception:
            similarity = 0.0

        if similarity > 1:
            similarity /= 100.0

        if similarity >= 0.90:

            risk_score = max(
                risk_score,
                85
            )

        elif similarity >= 0.80:

            risk_score = max(
                risk_score,
                80
            )

    # Strong domain evidence
    if domain_score >= 80:

        risk_score = max(
            risk_score,
            75
        )

    elif domain_score >= 65:

        risk_score = max(
            risk_score,
            65
        )

    elif domain_score >= 45:

        risk_score = max(
            risk_score,
            50
        )

    # High severity indicators
    if high_count >= 3:

        risk_score = max(
            risk_score,
            85
        )

    elif high_count >= 2:

        risk_score = max(
            risk_score,
            75
        )

    elif high_count == 1:

        risk_score = max(
            risk_score,
            60
        )

    # Multiple medium indicators
    if medium_count >= 5:

        risk_score = max(
            risk_score,
            65
        )

    elif medium_count >= 3:

        risk_score = max(
            risk_score,
            55
        )

    # --------------------------------------------------------
    # UNKNOWN DATABASE ENTRY
    # --------------------------------------------------------

    intelligence_status = str(
        threat_intelligence.get(
            "status",
            ""
        )
    ).upper()

    if (
        intelligence_status == "NOT_FOUND"
        and
        (
            rule_score >= 20
            or
            domain_score >= 25
            or
            typo_score >= 25
        )
    ):

        risk_score = max(
            risk_score,
            45
        )

    # --------------------------------------------------------
    # CLEAN URL
    # --------------------------------------------------------

    if (
        ml_probability <= 0.10
        and
        rule_score <= 5
        and
        domain_score <= 5
        and
        typo_score <= 5
        and
        not threat_matched
        and
        high_count == 0
        and
        medium_count == 0
    ):

        risk_score = min(
            risk_score,
            15
        )

    return max(
        0,
        min(
            int(round(risk_score)),
            100
        )
    )


# ============================================================
# COMPLETE URL ANALYSIS
# ============================================================

def analyze_url(
    url: str,
    ml_probability: float,
    threat_intelligence: dict,
    domain_analysis: dict = None,
    typosquatting: dict = None,
):

    if domain_analysis is None:
        domain_analysis = {}

    if typosquatting is None:
        typosquatting = {}

    if not isinstance(
        threat_intelligence,
        dict
    ):
        threat_intelligence = {}

    # --------------------------------------------------------
    # RULE ANALYSIS
    # --------------------------------------------------------

    rule_score, indicators = (
        analyze_url_rules(url)
    )

    # --------------------------------------------------------
    # THREAT TYPE
    # --------------------------------------------------------

    threat_type = classify_threat(
        url,
        indicators,
        typosquatting
    )

    # --------------------------------------------------------
    # HYBRID SCORE
    # --------------------------------------------------------

    risk_score = calculate_hybrid_risk(

        ml_probability=ml_probability,

        threat_intelligence=(
            threat_intelligence
        ),

        rule_score=rule_score,

        indicators=indicators,

        domain_analysis=(
            domain_analysis
        ),

        typosquatting=(
            typosquatting
        ),
    )

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    risk_level = get_risk_level(
        risk_score
    )

    # --------------------------------------------------------
    # ML
    # --------------------------------------------------------

    try:
        phishing_probability = float(
            ml_probability
        )
    except Exception:
        phishing_probability = 0.5

    phishing_probability = max(
        0.0,
        min(
            phishing_probability,
            1.0
        )
    )

    legitimate_probability = (
        1.0 -
        phishing_probability
    )

    if phishing_probability >= 0.80:

        ai_prediction = "PHISHING"

    elif phishing_probability <= 0.20:

        ai_prediction = "LEGITIMATE"

    else:

        ai_prediction = "UNCERTAIN"

    # --------------------------------------------------------
    # FINAL VERDICT
    # --------------------------------------------------------

    if risk_level in {
        "CRITICAL",
        "HIGH",
    }:

        final_verdict = "PHISHING"

    elif risk_level == "MEDIUM":

        final_verdict = "SUSPICIOUS"

    else:

        final_verdict = "LEGITIMATE"

    # --------------------------------------------------------
    # TYPOSQUATTING OVERRIDE
    # --------------------------------------------------------

    if bool(
        typosquatting.get(
            "detected",
            False
        )
    ):

        final_verdict = "PHISHING"

        risk_score = max(
            risk_score,
            75
        )

        risk_level = get_risk_level(
            risk_score
        )

    # --------------------------------------------------------
    # KNOWN THREAT OVERRIDE
    # --------------------------------------------------------

    threat_matched = bool(
        threat_intelligence.get(
            "matched",
            threat_intelligence.get(
                "known_threat",
                False
            )
        )
    )

    if threat_matched:

        final_verdict = "PHISHING"

        risk_score = max(
            risk_score,
            95
        )

        risk_level = get_risk_level(
            risk_score
        )

    # --------------------------------------------------------
    # STRONG STRUCTURAL EVIDENCE
    # --------------------------------------------------------

    strong_structural_evidence = (

        rule_score >= 30

        or

        _get_analysis_score(
            domain_analysis
        ) >= 35

        or

        _get_typo_score(
            typosquatting
        ) >= 35

        or

        len([
            item
            for item in indicators
            if str(
                item.get(
                    "severity",
                    ""
                )
            ).upper()
            == "HIGH"
        ]) >= 2
    )

    if (
        final_verdict == "LEGITIMATE"
        and
        strong_structural_evidence
    ):

        final_verdict = "SUSPICIOUS"

        risk_score = max(
            risk_score,
            45
        )

        risk_level = get_risk_level(
            risk_score
        )

    # --------------------------------------------------------
    # ATTACK ANALYSIS
    # --------------------------------------------------------

    attack_objective = (
        generate_attack_objective(
            threat_type
        )
    )

    attack_scenario = (
        generate_attack_scenario(
            threat_type
        )
    )

    potential_impact = (
        generate_potential_impact(
            threat_type,
            risk_level
        )
    )

    recommendation = (
        generate_recommendation(
            risk_level,
            threat_type
        )
    )

    # --------------------------------------------------------
    # RETURN
    # --------------------------------------------------------

    return {

        "final_verdict":
            final_verdict,

        "risk_score":
            risk_score,

        "risk_level":
            risk_level,

        "threat_type":
            threat_type,

        "attack_category": (
            "Cyber Threat → Phishing"
            if threat_type !=
            "No Significant Threat Detected"
            else
            "No Significant Threat"
        ),

        "attack_objective":
            attack_objective,

        "ai_prediction":
            ai_prediction,

        "phishing_probability":
            phishing_probability,

        "legitimate_probability":
            legitimate_probability,

        "rule_score":
            rule_score,

        "indicators":
            indicators,

        "domain_analysis":
            domain_analysis,

        "typosquatting":
            typosquatting,

        "threat_intelligence":
            threat_intelligence,

        "attack_scenario":
            attack_scenario,

        "potential_impact":
            potential_impact,

        "recommendation":
            recommendation,

        "analysis_summary": (
            "CyberSentinel combines machine learning, "
            "URL security analysis, domain intelligence, "
            "typosquatting detection and threat intelligence "
            "to produce a hybrid risk assessment. HTTPS is "
            "not treated as proof of legitimacy, and unknown "
            "domains are not automatically considered safe."
        ),
    }


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("CYBERSENTINEL HYBRID RISK ENGINE TEST")
    print("=" * 70)

    test_cases = [

        (
            "https://www.google.com",
            0.05,
            {
                "matched": False,
                "status": "NOT_FOUND",
                "threat_score": 0,
            },
            {
                "risk_score": 0,
            },
            {
                "detected": False,
                "similarity": 0.20,
                "score": 0,
            },
        ),

        (
            "https://gooogle.com",
            0.05,
            {
                "matched": False,
                "status": "NOT_FOUND",
                "threat_score": 0,
            },
            {
                "risk_score": 75,
            },
            {
                "detected": True,
                "brand": "google",
                "similarity": 0.857,
                "similarity_percent": 85.7,
                "score": 70,
            },
        ),

        (
            "https://tiktok2.com",
            0.01,
            {
                "matched": False,
                "status": "NOT_FOUND",
                "threat_score": 0,
            },
            {
                "risk_score": 70,
            },
            {
                "detected": True,
                "brand": "tiktok",
                "similarity": 0.857,
                "similarity_percent": 85.7,
                "score": 70,
            },
        ),

        (
            "https://amaz0n.com",
            0.01,
            {
                "matched": False,
                "status": "NOT_FOUND",
                "threat_score": 0,
            },
            {
                "risk_score": 85,
            },
            {
                "detected": True,
                "brand": "amazon",
                "similarity": 1.0,
                "similarity_percent": 100,
                "score": 85,
            },
        ),

        (
            "http://192.168.1.10/login",
            0.99,
            {
                "matched": False,
                "status": "NOT_FOUND",
                "threat_score": 0,
            },
            {},
            {},
        ),
    ]

    for (
        test_url,
        ml_probability,
        threat_intelligence,
        domain_analysis,
        typosquatting,
    ) in test_cases:

        print()
        print("-" * 70)
        print(
            f"URL: {test_url}"
        )

        try:

            result = analyze_url(

                url=test_url,

                ml_probability=(
                    ml_probability
                ),

                threat_intelligence=(
                    threat_intelligence
                ),

                domain_analysis=(
                    domain_analysis
                ),

                typosquatting=(
                    typosquatting
                ),
            )

            print(
                f"Verdict: "
                f"{result['final_verdict']}"
            )

            print(
                f"Risk score: "
                f"{result['risk_score']}/100"
            )

            print(
                f"Risk level: "
                f"{result['risk_level']}"
            )

            print(
                f"Threat type: "
                f"{result['threat_type']}"
            )

            print(
                f"AI prediction: "
                f"{result['ai_prediction']}"
            )

            print(
                f"AI phishing probability: "
                f"{result['phishing_probability']:.2%}"
            )

            print()
            print("Indicators:")

            for indicator in result[
                "indicators"
            ]:

                print(
                    "  • "
                    +
                    indicator.get(
                        "indicator",
                        "Unknown"
                    )
                    +
                    " ["
                    +
                    indicator.get(
                        "severity",
                        "UNKNOWN"
                    )
                    +
                    "]"
                )

        except Exception as error:

            print(
                f"ERROR: {error}"
            )

    print()
    print("=" * 70)
    print("TEST COMPLETED")
    print("=" * 70)