# ============================================================
# CYBERSENTINEL - DETAILED MESSAGE ANALYZER
# AI-POWERED CYBER THREAT DETECTION PLATFORM
# ============================================================

import re


# ============================================================
# SUSPICIOUS SOCIAL-ENGINEERING KEYWORDS
# ============================================================

URGENCY_WORDS = [
    "urgent",
    "immediately",
    "now",
    "asap",
    "expires",
    "deadline",
    "within 24 hours",
    "act now",
    "right away",
    "hurry",
    "immediate action"
]


CREDENTIAL_WORDS = [
    "password",
    "username",
    "login",
    "sign in",
    "signin",
    "credential",
    "credentials",
    "otp",
    "pin",
    "verification",
    "verify",
    "verify your account",
    "verify account",
    "security code",
    "authentication code",
    "one time password"
]


FINANCIAL_WORDS = [
    "bank",
    "bank account",
    "payment",
    "transaction",
    "refund",
    "money",
    "credit card",
    "debit card",
    "upi",
    "wallet",
    "account",
    "balance",
    "cash",
    "billing"
]


PRIZE_WORDS = [
    "winner",
    "won",
    "prize",
    "reward",
    "lottery",
    "bonus",
    "cash prize",
    "claim",
    "gift",
    "free money",
    "congratulations"
]


THREAT_WORDS = [
    "blocked",
    "suspended",
    "locked",
    "terminated",
    "disabled",
    "legal action",
    "penalty",
    "fine",
    "arrest",
    "police",
    "account will be closed",
    "account will be blocked"
]


ACTION_WORDS = [
    "click",
    "click here",
    "verify",
    "confirm",
    "update",
    "login",
    "sign in",
    "send",
    "provide",
    "enter",
    "submit",
    "claim",
    "activate"
]


SUSPICIOUS_PHRASES = [
    "verify your account",
    "confirm your identity",
    "verify your otp",
    "enter your otp",
    "send your otp",
    "provide your password",
    "confirm your password",
    "click here to verify",
    "account will be blocked",
    "account will be suspended",
    "claim your reward",
    "you have won",
    "security alert",
    "unusual activity",
    "unauthorized activity"
]


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(message: str):
    """
    Extract HTTP/HTTPS URLs from a message.
    """

    pattern = r"https?://[^\s]+"

    urls = re.findall(
        pattern,
        message
    )

    # Remove common trailing punctuation
    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,!?;:)]}")

        cleaned_urls.append(url)

    return cleaned_urls


# ============================================================
# KEYWORD DETECTION
# ============================================================

def find_keywords(message: str, keywords):

    message_lower = message.lower()

    found = []

    for keyword in keywords:

        if keyword.lower() in message_lower:

            found.append(keyword)

    return list(dict.fromkeys(found))


# ============================================================
# MESSAGE FEATURE EXTRACTION
# ============================================================

def extract_message_features(message: str):

    message_lower = message.lower()

    urls = extract_urls(message)

    urgency = find_keywords(
        message,
        URGENCY_WORDS
    )

    credentials = find_keywords(
        message,
        CREDENTIAL_WORDS
    )

    financial = find_keywords(
        message,
        FINANCIAL_WORDS
    )

    prizes = find_keywords(
        message,
        PRIZE_WORDS
    )

    threats = find_keywords(
        message,
        THREAT_WORDS
    )

    actions = find_keywords(
        message,
        ACTION_WORDS
    )

    suspicious_phrases = find_keywords(
        message,
        SUSPICIOUS_PHRASES
    )

    uppercase_count = sum(
        1
        for char in message
        if char.isupper()
    )

    features = {

        "message_length": len(message),

        "word_count": len(message.split()),

        "uppercase_count": uppercase_count,

        "uppercase_ratio":
            uppercase_count / max(len(message), 1),

        "exclamation_count":
            message.count("!"),

        "question_count":
            message.count("?"),

        "url_count":
            len(urls),

        "urgency_count":
            len(urgency),

        "credential_count":
            len(credentials),

        "financial_count":
            len(financial),

        "prize_count":
            len(prizes),

        "threat_count":
            len(threats),

        "action_count":
            len(actions),

        "suspicious_phrase_count":
            len(suspicious_phrases),

        "contains_otp":
            1 if "otp" in message_lower else 0,

        "contains_phone_number":
            1 if re.search(
                r"\b\d{10}\b",
                message
            ) else 0,

        "contains_money_symbol":
            1 if any(
                symbol in message
                for symbol in ["₹", "$", "€", "£"]
            ) else 0
    }

    return features


# ============================================================
# SOCIAL ENGINEERING RULE SCORE
# ============================================================

def calculate_message_rule_score(features):

    score = 0

    # --------------------------------------------------------
    # Individual indicators
    # --------------------------------------------------------

    score += min(
        features["urgency_count"] * 10,
        25
    )

    score += min(
        features["credential_count"] * 12,
        30
    )

    score += min(
        features["financial_count"] * 7,
        20
    )

    score += min(
        features["prize_count"] * 10,
        20
    )

    score += min(
        features["threat_count"] * 10,
        20
    )

    score += min(
        features["action_count"] * 4,
        12
    )

    if features["url_count"] > 0:
        score += 12

    score += min(
        features["suspicious_phrase_count"] * 10,
        25
    )

    if features["contains_otp"]:
        score += 10

    if features["contains_money_symbol"]:
        score += 5

    # --------------------------------------------------------
    # Contextual combinations
    # --------------------------------------------------------

    if (
        features["urgency_count"] > 0
        and features["credential_count"] > 0
    ):
        score += 20

    if (
        features["financial_count"] > 0
        and features["credential_count"] > 0
    ):
        score += 20

    if (
        features["threat_count"] > 0
        and features["credential_count"] > 0
    ):
        score += 20

    if (
        features["financial_count"] > 0
        and features["urgency_count"] > 0
    ):
        score += 15

    if (
        features["financial_count"] > 0
        and features["threat_count"] > 0
    ):
        score += 15

    if (
        features["prize_count"] > 0
        and features["urgency_count"] > 0
    ):
        score += 15

    if (
        features["url_count"] > 0
        and features["credential_count"] > 0
    ):
        score += 15

    return min(score, 100)


# ============================================================
# THREAT TYPE CLASSIFICATION
# ============================================================

def classify_message(message: str):

    features = extract_message_features(message)

    # Credential phishing
    if (
        features["credential_count"] > 0
        and (
            features["urgency_count"] > 0
            or features["threat_count"] > 0
        )
    ):
        return "Credential Phishing"

    # Financial phishing
    if (
        features["financial_count"] > 0
        and features["credential_count"] > 0
    ):
        return "Financial Phishing"

    # Prize scam
    if features["prize_count"] > 0:
        return "Prize Scam"

    # Financial scam
    if features["financial_count"] > 0:
        return "Financial Scam"

    # Threat-based scam
    if features["threat_count"] > 0:
        return "Threat-Based Scam"

    # Suspicious URL message
    if features["url_count"] > 0:
        return "Suspicious Message"

    # General social engineering
    if (
        features["urgency_count"] > 0
        and features["action_count"] > 0
    ):
        return "Social Engineering"

    return "Potentially Safe Message"


# ============================================================
# ATTACK CATEGORY
# ============================================================

def classify_attack_category(threat_type):

    categories = {

        "Credential Phishing":
            "Cyber Threat → Social Engineering → Credential Phishing",

        "Financial Phishing":
            "Cyber Threat → Social Engineering → Financial Phishing",

        "Financial Scam":
            "Cyber Threat → Social Engineering → Financial Scam",

        "Prize Scam":
            "Cyber Threat → Social Engineering → Prize / Reward Scam",

        "Threat-Based Scam":
            "Cyber Threat → Social Engineering → Threat-Based Scam",

        "Suspicious Message":
            "Cyber Threat → Suspicious Link / Social Engineering",

        "Social Engineering":
            "Cyber Threat → Social Engineering",

        "Potentially Safe Message":
            "No confirmed cyber-threat category"
    }

    return categories.get(
        threat_type,
        "Cyber Threat → Unknown / Unclassified"
    )


# ============================================================
# ATTACK OBJECTIVE
# ============================================================

def determine_attack_objective(
    threat_type,
    features
):

    if threat_type == "Credential Phishing":

        return (
            "The likely objective is to obtain authentication "
            "information such as usernames, passwords, OTPs, "
            "PINs or security codes. The attacker may use this "
            "information to gain unauthorized access to an account."
        )

    if threat_type == "Financial Phishing":

        return (
            "The likely objective is to obtain banking, payment "
            "or financial information. Such information could "
            "potentially be used for unauthorized transactions "
            "or financial fraud."
        )

    if threat_type == "Financial Scam":

        return (
            "The likely objective is to manipulate the victim "
            "into transferring money, making a payment or "
            "revealing financial information."
        )

    if threat_type == "Prize Scam":

        return (
            "The likely objective is to convince the victim that "
            "they have received a prize or reward and then obtain "
            "money, personal information or further interaction."
        )

    if threat_type == "Threat-Based Scam":

        return (
            "The likely objective is to create fear or panic "
            "using account suspension, penalties or other "
            "consequences so that the victim performs the "
            "requested action."
        )

    if threat_type == "Suspicious Message":

        return (
            "The likely objective is to redirect the recipient "
            "toward an external destination that requires "
            "additional verification before interaction."
        )

    if features["action_count"] > 0:

        return (
            "The message attempts to influence the recipient "
            "into performing a potentially unsafe action."
        )

    return (
        "No clear malicious objective was established from "
        "the available indicators."
    )


# ============================================================
# WHAT IS THE THREAT?
# ============================================================

def generate_threat_explanation(
    threat_type,
    features
):

    if threat_type == "Credential Phishing":

        return (
            "Credential phishing is a social-engineering attack "
            "in which an attacker attempts to trick a victim into "
            "revealing authentication information. The message "
            "may imitate a trusted organization or create a "
            "security-related situation that encourages the victim "
            "to log in, verify an account or provide a security code."
        )

    if threat_type == "Financial Phishing":

        return (
            "Financial phishing is an attack that combines social "
            "engineering with financial or banking context. The "
            "attacker attempts to convince the victim to disclose "
            "banking credentials, payment information or other "
            "sensitive financial details."
        )

    if threat_type == "Financial Scam":

        return (
            "A financial scam attempts to manipulate a victim into "
            "sending money or revealing financial information. "
            "The attacker may use false payment requests, refunds, "
            "financial opportunities or account-related claims."
        )

    if threat_type == "Prize Scam":

        return (
            "A prize or reward scam attempts to convince a victim "
            "that they have won something valuable. The attacker "
            "may then request personal information, payment or "
            "additional actions to supposedly claim the reward."
        )

    if threat_type == "Threat-Based Scam":

        return (
            "A threat-based social-engineering attack uses fear, "
            "panic or the possibility of a negative consequence "
            "to influence the victim's behavior."
        )

    if threat_type == "Suspicious Message":

        return (
            "The message contains an external URL or other "
            "characteristics that require additional verification. "
            "The presence of a link alone does not prove that the "
            "destination is malicious, so the URL should be "
            "independently verified."
        )

    if threat_type == "Social Engineering":

        return (
            "The message contains behavioral manipulation "
            "characteristics such as urgency and action requests. "
            "These techniques are commonly used to influence a "
            "recipient into making a decision without sufficient "
            "verification."
        )

    return (
        "The analyzer did not identify enough evidence to confirm "
        "a specific cyber-threat category."
    )


# ============================================================
# DETAILED DETECTION REASONS
# ============================================================

def generate_detection_reasons(
    message,
    features
):

    reasons = []

    urgency = find_keywords(
        message,
        URGENCY_WORDS
    )

    credentials = find_keywords(
        message,
        CREDENTIAL_WORDS
    )

    financial = find_keywords(
        message,
        FINANCIAL_WORDS
    )

    prizes = find_keywords(
        message,
        PRIZE_WORDS
    )

    threats = find_keywords(
        message,
        THREAT_WORDS
    )

    actions = find_keywords(
        message,
        ACTION_WORDS
    )

    phrases = find_keywords(
        message,
        SUSPICIOUS_PHRASES
    )

    if urgency:

        reasons.append({
            "indicator": "Urgency / Time Pressure",
            "evidence": urgency,
            "severity": "MEDIUM",
            "explanation": (
                "The message uses time pressure to encourage "
                "the recipient to act quickly. Urgency can reduce "
                "the amount of time a victim spends verifying a request."
            ),
            "security_significance": (
                "This can be used as a social-engineering technique "
                "to discourage careful verification."
            )
        })

    if credentials:

        reasons.append({
            "indicator": "Credential / Authentication Request",
            "evidence": credentials,
            "severity": "HIGH",
            "explanation": (
                "The message contains authentication-related "
                "language such as login, password, verification, "
                "PIN or OTP."
            ),
            "security_significance": (
                "Authentication information is highly sensitive "
                "and is a common target in credential-phishing attacks."
            )
        })

    if financial:

        reasons.append({
            "indicator": "Financial Context",
            "evidence": financial,
            "severity": "HIGH",
            "explanation": (
                "The message references financial services, "
                "payments, accounts or monetary information."
            ),
            "security_significance": (
                "Financial context increases the potential impact "
                "because attackers may attempt to obtain payment "
                "information or initiate fraudulent transactions."
            )
        })

    if threats:

        reasons.append({
            "indicator": "Threatening / Fear-Based Language",
            "evidence": threats,
            "severity": "HIGH",
            "explanation": (
                "The message suggests account blocking, suspension, "
                "penalties or other negative consequences."
            ),
            "security_significance": (
                "Fear can pressure victims into following instructions "
                "without independently verifying the sender."
            )
        })

    if prizes:

        reasons.append({
            "indicator": "Prize / Reward Language",
            "evidence": prizes,
            "severity": "HIGH",
            "explanation": (
                "The message refers to a prize, reward, lottery "
                "or unexpected benefit."
            ),
            "security_significance": (
                "Unexpected rewards can be used as a lure to obtain "
                "personal information, money or additional interaction."
            )
        })

    if actions:

        reasons.append({
            "indicator": "Action Request",
            "evidence": actions,
            "severity": "MEDIUM",
            "explanation": (
                "The recipient is asked to click, verify, confirm, "
                "enter, provide or submit information."
            ),
            "security_significance": (
                "Action-oriented requests can move a victim from "
                "reading a message to interacting with an attacker-controlled "
                "resource."
            )
        })

    if features["url_count"] > 0:

        reasons.append({
            "indicator": "Embedded URL",
            "evidence": extract_urls(message),
            "severity": "MEDIUM",
            "explanation": (
                "The message contains an HTTP/HTTPS URL."
            ),
            "security_significance": (
                "External links can redirect victims to websites "
                "that require additional security analysis."
            )
        })

    if phrases:

        reasons.append({
            "indicator": "Known Social-Engineering Phrase",
            "evidence": phrases,
            "severity": "HIGH",
            "explanation": (
                "The message contains wording commonly associated "
                "with phishing or social-engineering campaigns."
            ),
            "security_significance": (
                "Repeated phishing patterns can indicate an attempt "
                "to imitate known social-engineering scenarios."
            )
        })

    if features["contains_otp"]:

        reasons.append({
            "indicator": "OTP Reference",
            "evidence": ["OTP"],
            "severity": "CRITICAL",
            "explanation": (
                "The message specifically references one-time "
                "password information."
            ),
            "security_significance": (
                "OTP codes are authentication secrets and should "
                "never be disclosed to an unexpected requester."
            )
        })

    if not reasons:

        reasons.append({
            "indicator": "No Strong Indicator",
            "evidence": [],
            "severity": "LOW",
            "explanation": (
                "The rule-based analyzer did not identify strong "
                "social-engineering characteristics."
            ),
            "security_significance": (
                "The absence of detected indicators does not "
                "guarantee that a message is safe."
            )
        })

    return reasons


# ============================================================
# ATTACK CHAIN
# ============================================================

def generate_attack_scenario(
    threat_type,
    features
):

    if threat_type == "Credential Phishing":

        return [
            {
                "step": 1,
                "title": "Initial Delivery",
                "description": (
                    "The attacker delivers a deceptive message "
                    "to the intended victim."
                )
            },
            {
                "step": 2,
                "title": "Social Engineering",
                "description": (
                    "The message creates urgency, fear, account "
                    "verification pressure or another believable scenario."
                )
            },
            {
                "step": 3,
                "title": "Victim Interaction",
                "description": (
                    "The victim may click a link or follow instructions "
                    "contained in the message."
                )
            },
            {
                "step": 4,
                "title": "Credential Collection",
                "description": (
                    "A fraudulent workflow may attempt to collect "
                    "usernames, passwords, OTPs, PINs or other secrets."
                )
            },
            {
                "step": 5,
                "title": "Potential Account Compromise",
                "description": (
                    "Captured authentication information could potentially "
                    "be used for unauthorized access or further attacks."
                )
            }
        ]

    if threat_type == "Financial Phishing":

        return [
            {
                "step": 1,
                "title": "Deceptive Message",
                "description": (
                    "The attacker sends a message containing banking "
                    "or payment-related context."
                )
            },
            {
                "step": 2,
                "title": "Trust Manipulation",
                "description": (
                    "The attacker attempts to make the request appear "
                    "legitimate or urgent."
                )
            },
            {
                "step": 3,
                "title": "Information Request",
                "description": (
                    "The victim may be asked for banking, payment or "
                    "authentication information."
                )
            },
            {
                "step": 4,
                "title": "Potential Financial Abuse",
                "description": (
                    "Obtained information could potentially be misused "
                    "for unauthorized transactions or fraud."
                )
            }
        ]

    if threat_type == "Financial Scam":

        return [
            {
                "step": 1,
                "title": "Financial Claim",
                "description": (
                    "The attacker presents a financial opportunity, "
                    "payment problem or refund-related scenario."
                )
            },
            {
                "step": 2,
                "title": "Victim Manipulation",
                "description": (
                    "The victim is encouraged to respond quickly "
                    "or trust the provided instructions."
                )
            },
            {
                "step": 3,
                "title": "Payment / Information Request",
                "description": (
                    "The attacker may request money or sensitive "
                    "financial information."
                )
            },
            {
                "step": 4,
                "title": "Potential Loss",
                "description": (
                    "The victim may experience financial loss or "
                    "exposure of financial information."
                )
            }
        ]

    if threat_type == "Prize Scam":

        return [
            {
                "step": 1,
                "title": "Prize Claim",
                "description": (
                    "The attacker claims that the victim has won "
                    "a prize, reward or benefit."
                )
            },
            {
                "step": 2,
                "title": "Claim Process",
                "description": (
                    "The victim is encouraged to follow instructions "
                    "to receive the supposed reward."
                )
            },
            {
                "step": 3,
                "title": "Information / Payment Request",
                "description": (
                    "The attacker may request personal information, "
                    "money or other sensitive data."
                )
            }
        ]

    if threat_type == "Threat-Based Scam":

        return [
            {
                "step": 1,
                "title": "Threat Creation",
                "description": (
                    "The attacker presents a negative consequence "
                    "such as account suspension or penalties."
                )
            },
            {
                "step": 2,
                "title": "Fear and Urgency",
                "description": (
                    "The victim is pressured to respond before "
                    "they can properly verify the request."
                )
            },
            {
                "step": 3,
                "title": "Requested Action",
                "description": (
                    "The victim may be encouraged to click, verify "
                    "or provide sensitive information."
                )
            }
        ]

    if threat_type == "Suspicious Message":

        return [
            {
                "step": 1,
                "title": "External Link Delivery",
                "description": (
                    "The message contains an external HTTP/HTTPS URL."
                )
            },
            {
                "step": 2,
                "title": "User Redirection",
                "description": (
                    "The recipient may be encouraged to open the link."
                )
            },
            {
                "step": 3,
                "title": "Destination Interaction",
                "description": (
                    "The destination should be independently verified "
                    "before credentials or sensitive information are entered."
                )
            }
        ]

    return [
        {
            "step": 1,
            "title": "Message Analysis",
            "description": (
                "CyberSentinel analyzed the submitted content "
                "for social-engineering indicators."
            )
        },
        {
            "step": 2,
            "title": "Risk Assessment",
            "description": (
                "The detected indicators were evaluated using "
                "the rule-based security engine."
            )
        }
    ]


# ============================================================
# POTENTIAL IMPACT
# ============================================================

def generate_potential_impact(
    threat_type,
    features
):

    impacts = []

    if (
        threat_type == "Credential Phishing"
        or features["credential_count"] > 0
    ):

        impacts.extend([
            {
                "impact": "Credential Theft",
                "severity": "HIGH",
                "description": (
                    "Passwords, usernames, PINs or other authentication "
                    "information could potentially be exposed."
                )
            },
            {
                "impact": "Account Takeover",
                "severity": "HIGH",
                "description": (
                    "Compromised credentials could potentially be used "
                    "to gain unauthorized access to an account."
                )
            }
        ])

    if (
        threat_type in [
            "Financial Phishing",
            "Financial Scam"
        ]
        or features["financial_count"] > 0
    ):

        impacts.extend([
            {
                "impact": "Financial Loss",
                "severity": "HIGH",
                "description": (
                    "The victim may be exposed to unauthorized payments "
                    "or financial fraud."
                )
            },
            {
                "impact": "Financial Information Exposure",
                "severity": "HIGH",
                "description": (
                    "Banking, payment or card-related information "
                    "could potentially be exposed."
                )
            }
        ])

    if features["contains_otp"]:

        impacts.append({
            "impact": "Authentication Compromise",
            "severity": "CRITICAL",
            "description": (
                "Disclosure of an OTP can potentially weaken the "
                "victim's authentication security."
            )
        })

    if features["url_count"] > 0:

        impacts.append({
            "impact": "Unsafe Website Exposure",
            "severity": "MEDIUM",
            "description": (
                "The embedded URL could redirect the victim to "
                "a fraudulent or unsafe destination."
            )
        })

    if features["prize_count"] > 0:

        impacts.append({
            "impact": "Personal Information Exposure",
            "severity": "MEDIUM",
            "description": (
                "Prize-related interactions may request personal "
                "information or payment details."
            )
        })

    if not impacts:

        impacts.append({
            "impact": "Limited Evidence",
            "severity": "LOW",
            "description": (
                "No specific high-impact consequence was established "
                "from the detected indicators."
            )
        })

    return impacts


# ============================================================
# RISK ANALYSIS
# ============================================================

def generate_risk_analysis(
    threat_type,
    features,
    rule_score
):

    risks = []

    credential_risk = "LOW"
    financial_risk = "LOW"
    social_engineering_risk = "LOW"
    link_risk = "LOW"

    if features["credential_count"] > 0:

        credential_risk = "HIGH"

        risks.append({
            "category": "Credential Theft Risk",
            "level": "HIGH",
            "explanation": (
                "Authentication-related terminology was detected. "
                "This creates a potential credential-theft risk if "
                "the message attempts to direct the victim toward a "
                "fraudulent login or verification process."
            )
        })

    if features["financial_count"] > 0:

        financial_risk = "HIGH"

        risks.append({
            "category": "Financial Risk",
            "level": "HIGH",
            "explanation": (
                "Financial terminology was detected. If the message "
                "is malicious, the attacker may be attempting to obtain "
                "financial information or influence a payment-related action."
            )
        })

    if (
        features["urgency_count"] > 0
        or features["threat_count"] > 0
        or features["prize_count"] > 0
    ):

        social_engineering_risk = "HIGH"

        risks.append({
            "category": "Social Engineering Risk",
            "level": "HIGH",
            "explanation": (
                "The message contains psychological manipulation "
                "signals such as urgency, fear, threats or rewards. "
                "These techniques can influence a victim to act "
                "before independently verifying the request."
            )
        })

    if features["url_count"] > 0:

        link_risk = "MEDIUM"

        risks.append({
            "category": "Link Interaction Risk",
            "level": "MEDIUM",
            "explanation": (
                "An external URL was detected. The link should be "
                "verified independently before it is opened or used."
            )
        })

    if not risks:

        risks.append({
            "category": "General Risk",
            "level": "LOW",
            "explanation": (
                "No major risk category was strongly supported "
                "by the available rule-based evidence."
            )
        })

    return {
        "overall_rule_score": rule_score,
        "credential_risk": credential_risk,
        "financial_risk": financial_risk,
        "social_engineering_risk": social_engineering_risk,
        "link_risk": link_risk,
        "categories": risks
    }


# ============================================================
# RECOMMENDATIONS
# ============================================================

def generate_recommendations(
    threat_type,
    features
):

    recommendations = []

    # URL
    if features["url_count"] > 0:

        recommendations.append({
            "priority": "HIGH",
            "action": "Do not click the embedded URL.",
            "reason": (
                "The destination has not been independently verified."
            )
        })

    # Credentials
    if features["credential_count"] > 0:

        recommendations.append({
            "priority": "CRITICAL",
            "action": (
                "Do not provide passwords, usernames, PINs or OTPs."
            ),
            "reason": (
                "Authentication information is highly sensitive "
                "and should not be disclosed to unexpected requests."
            )
        })

    # Financial
    if features["financial_count"] > 0:

        recommendations.append({
            "priority": "CRITICAL",
            "action": (
                "Do not provide banking, card or payment information."
            ),
            "reason": (
                "Financial information could be misused for fraud."
            )
        })

    # Urgency
    if features["urgency_count"] > 0:

        recommendations.append({
            "priority": "HIGH",
            "action": (
                "Do not allow urgency to influence your decision."
            ),
            "reason": (
                "Verify the request independently before taking action."
            )
        })

    # Threat
    if features["threat_count"] > 0:

        recommendations.append({
            "priority": "HIGH",
            "action": (
                "Verify account warnings through the official organization."
            ),
            "reason": (
                "Attackers may use fear of suspension or penalties "
                "to manipulate victims."
            )
        })

    # Prize
    if features["prize_count"] > 0:

        recommendations.append({
            "priority": "HIGH",
            "action": (
                "Do not send money to claim an unexpected prize."
            ),
            "reason": (
                "Unexpected prize claims are commonly used as scam lures."
            )
        })

    # Always useful
    recommendations.append({
        "priority": "MEDIUM",
        "action": (
            "Verify the sender through an independent trusted channel."
        ),
        "reason": (
            "Do not rely solely on contact details supplied in the message."
        )
    })

    recommendations.append({
        "priority": "MEDIUM",
        "action": (
            "Access important services through their official website "
            "or application."
        ),
        "reason": (
            "Using a known official entry point reduces exposure to "
            "fraudulent links."
        )
    })

    recommendations.append({
        "priority": "MEDIUM",
        "action": (
            "Report the message as phishing or spam when appropriate."
        ),
        "reason": (
            "Reporting helps security teams identify and respond "
            "to suspicious campaigns."
        )
    })

    # If credentials may already have been exposed
    if threat_type == "Credential Phishing":

        recommendations.append({
            "priority": "CRITICAL",
            "action": (
                "If credentials were already submitted, change the "
                "password using the legitimate service."
            ),
            "reason": (
                "Changing the password can reduce the risk of continued "
                "unauthorized access."
            )
        })

        recommendations.append({
            "priority": "HIGH",
            "action": (
                "Enable multi-factor authentication where available."
            ),
            "reason": (
                "Additional authentication factors can provide "
                "an extra layer of protection."
            )
        })

    return recommendations


# ============================================================
# INCIDENT RESPONSE
# ============================================================

def generate_incident_response(threat_type):

    if threat_type == "Credential Phishing":

        return [
            "Stop interacting with the suspicious message or website.",
            "Change the affected password through the legitimate service.",
            "Change the same password on other services if it was reused.",
            "Enable multi-factor authentication where available.",
            "Review recent account activity for unauthorized access.",
            "Report the phishing message to the relevant organization or platform."
        ]

    if threat_type in [
        "Financial Phishing",
        "Financial Scam"
    ]:

        return [
            "Contact the financial institution through its official channel.",
            "Review recent transactions for unauthorized activity.",
            "Do not provide additional payment information.",
            "Follow the institution's fraud-reporting procedure."
        ]

    return [
        "Stop interacting with the suspicious content.",
        "Verify the sender through an independent trusted channel.",
        "Report the suspicious message when appropriate.",
        "Monitor the relevant account for unusual activity."
    ]


# ============================================================
# SECURITY GUIDANCE
# ============================================================

def generate_security_guidance(
    threat_type,
    rule_score
):

    guidance = []

    if rule_score >= 70:

        guidance.append(
            "HIGH RISK: Avoid interacting with the message, links "
            "or requests for sensitive information."
        )

    elif rule_score >= 40:

        guidance.append(
            "MEDIUM RISK: Independently verify the message before "
            "taking any requested action."
        )

    elif rule_score > 0:

        guidance.append(
            "LOW-TO-MODERATE RISK: Some suspicious characteristics "
            "were detected, so unexpected requests should still be verified."
        )

    else:

        guidance.append(
            "No strong malicious pattern was identified by the "
            "rule engine, but unexpected requests should still be verified."
        )

    guidance.extend([
        "Never share passwords, OTPs, PINs or authentication codes "
        "with an unexpected requester.",

        "Do not trust links simply because they appear to mention "
        "a familiar company or service.",

        "Access important accounts through official applications "
        "or manually entered/bookmarked websites.",

        "When in doubt, verify the request using a trusted communication channel."
    ])

    return guidance


# ============================================================
# EXPLAINABLE INDICATORS
# ============================================================

def generate_message_indicators(message: str):

    features = extract_message_features(message)

    indicators = []

    # --------------------------------------------------------
    # Urgency
    # --------------------------------------------------------

    if features["urgency_count"] > 0:

        indicators.append({

            "indicator": "Urgency language",

            "explanation": (
                "The message pressures the recipient to act quickly. "
                "Urgency can reduce the time available for verification."
            ),

            "evidence":
                find_keywords(
                    message,
                    URGENCY_WORDS
                ),

            "severity": "MEDIUM"
        })

    # --------------------------------------------------------
    # Credentials
    # --------------------------------------------------------

    if features["credential_count"] > 0:

        indicators.append({

            "indicator": "Credential request",

            "explanation": (
                "The message contains language related to passwords, "
                "login, verification, PIN or OTP."
            ),

            "evidence":
                find_keywords(
                    message,
                    CREDENTIAL_WORDS
                ),

            "severity": "HIGH"
        })

    # --------------------------------------------------------
    # Financial
    # --------------------------------------------------------

    if features["financial_count"] > 0:

        indicators.append({

            "indicator": "Financial context",

            "explanation": (
                "The message references banking, payments, accounts "
                "or financial information."
            ),

            "evidence":
                find_keywords(
                    message,
                    FINANCIAL_WORDS
                ),

            "severity": "HIGH"
        })

    # --------------------------------------------------------
    # Prize
    # --------------------------------------------------------

    if features["prize_count"] > 0:

        indicators.append({

            "indicator": "Prize or reward language",

            "explanation": (
                "The message claims a prize, reward or unexpected benefit."
            ),

            "evidence":
                find_keywords(
                    message,
                    PRIZE_WORDS
                ),

            "severity": "HIGH"
        })

    # --------------------------------------------------------
    # Threat
    # --------------------------------------------------------

    if features["threat_count"] > 0:

        indicators.append({

            "indicator": "Threatening language",

            "explanation": (
                "The message threatens account suspension, blocking, "
                "penalties or other consequences."
            ),

            "evidence":
                find_keywords(
                    message,
                    THREAT_WORDS
                ),

            "severity": "HIGH"
        })

    # --------------------------------------------------------
    # Action
    # --------------------------------------------------------

    if features["action_count"] > 0:

        indicators.append({

            "indicator": "Action request",

            "explanation": (
                "The message asks the recipient to click, verify, "
                "confirm, provide information or take another action."
            ),

            "evidence":
                find_keywords(
                    message,
                    ACTION_WORDS
                ),

            "severity": "MEDIUM"
        })

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    if features["url_count"] > 0:

        indicators.append({

            "indicator": "Embedded URL",

            "explanation": (
                "The message contains a clickable URL that may require "
                "additional security analysis."
            ),

            "evidence":
                extract_urls(message),

            "severity": "MEDIUM"
        })

    # --------------------------------------------------------
    # Suspicious phrases
    # --------------------------------------------------------

    if features["suspicious_phrase_count"] > 0:

        indicators.append({

            "indicator": "Known social-engineering phrase",

            "explanation": (
                "The message contains wording commonly associated "
                "with phishing or social-engineering attempts."
            ),

            "evidence":
                find_keywords(
                    message,
                    SUSPICIOUS_PHRASES
                ),

            "severity": "HIGH"
        })

    return indicators


# ============================================================
# DETECTION CONFIDENCE
# ============================================================

def determine_detection_confidence(rule_score):

    if rule_score >= 75:
        return {
            "level": "HIGH",
            "description": (
                "The rule engine detected multiple strong indicators "
                "consistent with social engineering."
            )
        }

    if rule_score >= 45:
        return {
            "level": "MEDIUM",
            "description": (
                "Several suspicious indicators were detected, "
                "but independent verification is recommended."
            )
        }

    if rule_score > 0:
        return {
            "level": "LOW",
            "description": (
                "Some suspicious characteristics were detected, "
                "but the available rule-based evidence is limited."
            )
        }

    return {
        "level": "MINIMAL",
        "description": (
            "The rule engine did not detect significant "
            "social-engineering indicators."
        )
    }


# ============================================================
# FINAL SECURITY CONCLUSION
# ============================================================

def generate_final_conclusion(
    threat_type,
    rule_score,
    features
):

    if rule_score >= 70:

        return (
            f"CyberSentinel identified strong indicators associated "
            f"with {threat_type.lower()}. The rule-based engine "
            f"assigned a score of {rule_score}/100. The combination "
            f"of detected indicators warrants treating the message "
            f"as high risk and avoiding interaction with links or "
            f"requests for sensitive information."
        )

    if rule_score >= 40:

        return (
            f"CyberSentinel identified several characteristics "
            f"associated with {threat_type.lower()}. The rule-based "
            f"engine assigned a score of {rule_score}/100. The "
            f"available evidence is sufficient to recommend caution "
            f"and independent verification before interacting with "
            f"the message."
        )

    if rule_score > 0:

        return (
            f"CyberSentinel detected some potentially suspicious "
            f"characteristics associated with {threat_type.lower()}, "
            f"with a rule score of {rule_score}/100. The evidence "
            f"is limited, so the message should be verified before "
            f"taking any sensitive action."
        )

    return (
        "CyberSentinel did not detect significant social-engineering "
        "indicators in the submitted message. This does not guarantee "
        "that the message is completely safe, because automated "
        "analysis cannot establish trust from the absence of indicators alone."
    )


# ============================================================
# COMPLETE MESSAGE ANALYSIS
# ============================================================

def analyze_message_rules(message: str):
    """
    Complete explainable message analysis.

    Returns detailed information for the CyberSentinel
    frontend report.
    """

    if not isinstance(message, str):
        message = str(message)

    message = message.strip()

    # --------------------------------------------------------
    # Feature extraction
    # --------------------------------------------------------

    features = extract_message_features(message)

    # --------------------------------------------------------
    # Rule score
    # --------------------------------------------------------

    rule_score = calculate_message_rule_score(
        features
    )

    # --------------------------------------------------------
    # Threat type
    # --------------------------------------------------------

    threat_type = classify_message(
        message
    )

    # --------------------------------------------------------
    # Attack category
    # --------------------------------------------------------

    attack_category = classify_attack_category(
        threat_type
    )

    # --------------------------------------------------------
    # Attack objective
    # --------------------------------------------------------

    attack_objective = determine_attack_objective(
        threat_type,
        features
    )

    # --------------------------------------------------------
    # Threat explanation
    # --------------------------------------------------------

    threat_explanation = generate_threat_explanation(
        threat_type,
        features
    )

    # --------------------------------------------------------
    # Detection reasons
    # --------------------------------------------------------

    reasons = generate_detection_reasons(
        message,
        features
    )

    # --------------------------------------------------------
    # Indicators
    # --------------------------------------------------------

    indicators = generate_message_indicators(
        message
    )

    # --------------------------------------------------------
    # Attack scenario
    # --------------------------------------------------------

    attack_scenario = generate_attack_scenario(
        threat_type,
        features
    )

    # --------------------------------------------------------
    # Potential impact
    # --------------------------------------------------------

    potential_impact = generate_potential_impact(
        threat_type,
        features
    )

    # --------------------------------------------------------
    # Risk analysis
    # --------------------------------------------------------

    risk_analysis = generate_risk_analysis(
        threat_type,
        features,
        rule_score
    )

    # --------------------------------------------------------
    # Recommendations
    # --------------------------------------------------------

    recommendations = generate_recommendations(
        threat_type,
        features
    )

    # --------------------------------------------------------
    # Incident response
    # --------------------------------------------------------

    incident_response = generate_incident_response(
        threat_type
    )

    # --------------------------------------------------------
    # Security guidance
    # --------------------------------------------------------

    security_guidance = generate_security_guidance(
        threat_type,
        rule_score
    )

    # --------------------------------------------------------
    # Detection confidence
    # --------------------------------------------------------

    detection_confidence = determine_detection_confidence(
        rule_score
    )

    # --------------------------------------------------------
    # Final conclusion
    # --------------------------------------------------------

    final_conclusion = generate_final_conclusion(
        threat_type,
        rule_score,
        features
    )

    # --------------------------------------------------------
    # Detailed analysis summary
    # --------------------------------------------------------

    analysis_summary = (
        f"CyberSentinel classified the submitted content as "
        f"'{threat_type}' after examining message characteristics, "
        f"social-engineering indicators and contextual security signals. "
        f"The rule-based engine produced a score of {rule_score}/100. "
        f"The score reflects the presence and combination of indicators "
        f"such as authentication requests, urgency, financial context, "
        f"threatening language, action requests and suspicious phrases."
    )

    # --------------------------------------------------------
    # Return complete result
    # --------------------------------------------------------

    return {

        # ====================================================
        # CORE RESULT
        # ====================================================

        "rule_score":
            rule_score,

        "threat_type":
            threat_type,

        "attack_category":
            attack_category,

        "attack_objective":
            attack_objective,

        "detection_confidence":
            detection_confidence,


        # ====================================================
        # THREAT EXPLANATION
        # ====================================================

        "threat_explanation":
            threat_explanation,

        "analysis_summary":
            analysis_summary,

        "reasons":
            reasons,


        # ====================================================
        # SECURITY INDICATORS
        # ====================================================

        "indicators":
            indicators,


        # ====================================================
        # ATTACK SCENARIO
        # ====================================================

        "attack_scenario":
            attack_scenario,


        # ====================================================
        # RISK
        # ====================================================

        "risk_analysis":
            risk_analysis,

        "potential_impact":
            potential_impact,


        # ====================================================
        # PREVENTION
        # ====================================================

        "recommendations":
            recommendations,

        "incident_response":
            incident_response,

        "security_guidance":
            security_guidance,


        # ====================================================
        # EXTRACTED DATA
        # ====================================================

        "extracted_urls":
            extract_urls(message),

        "detected_keywords": {

            "urgency":
                find_keywords(
                    message,
                    URGENCY_WORDS
                ),

            "credentials":
                find_keywords(
                    message,
                    CREDENTIAL_WORDS
                ),

            "financial":
                find_keywords(
                    message,
                    FINANCIAL_WORDS
                ),

            "prizes":
                find_keywords(
                    message,
                    PRIZE_WORDS
                ),

            "threats":
                find_keywords(
                    message,
                    THREAT_WORDS
                ),

            "actions":
                find_keywords(
                    message,
                    ACTION_WORDS
                ),

            "suspicious_phrases":
                find_keywords(
                    message,
                    SUSPICIOUS_PHRASES
                )
        },


        # ====================================================
        # RAW FEATURES
        # ====================================================

        "features":
            features,


        # ====================================================
        # REPORT METADATA
        # ====================================================

        "report": {

            "platform":
                "CyberSentinel",

            "report_type":
                "AI-Powered Cyber Threat Detection Report",

            "analysis_engine":
                "Rule-Based Social Engineering Analyzer",

            "analysis_status":
                "Completed",

            "disclaimer":
                (
                    "Automated analysis provides security indicators "
                    "and risk assessment. A detection result does not "
                    "by itself establish malicious intent or guarantee "
                    "that a destination is safe."
                )
        }
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_message = """
    URGENT! Your bank account will be blocked.
    Verify your password and OTP immediately:
    https://example.com/login
    """

    result = analyze_message_rules(
        test_message
    )

    print()
    print("=" * 70)
    print("              CYBERSENTINEL")
    print("       DETAILED MESSAGE SECURITY ANALYSIS")
    print("=" * 70)

    print("\nTHREAT TYPE:")
    print(result["threat_type"])

    print("\nATTACK CATEGORY:")
    print(result["attack_category"])

    print("\nATTACK OBJECTIVE:")
    print(result["attack_objective"])

    print("\nWHAT IS THE THREAT?")
    print(result["threat_explanation"])

    print("\nRULE SCORE:")
    print(f"{result['rule_score']} / 100")

    print("\nDETECTION CONFIDENCE:")
    print(
        result["detection_confidence"]["level"]
    )

    print("\nANALYSIS SUMMARY:")
    print(result["analysis_summary"])

    print("\n" + "=" * 70)
    print("WHY WAS THIS THREAT DETECTED?")
    print("=" * 70)

    for reason in result["reasons"]:

        print(
            f"\n[{reason['severity']}] "
            f"{reason['indicator']}"
        )

        print(
            f"Evidence: {reason['evidence']}"
        )

        print(
            f"Explanation: {reason['explanation']}"
        )

        print(
            f"Security Significance: "
            f"{reason['security_significance']}"
        )

    print("\n" + "=" * 70)
    print("ATTACK SCENARIO")
    print("=" * 70)

    for step in result["attack_scenario"]:

        print(
            f"\nStep {step['step']}: "
            f"{step['title']}"
        )

        print(
            step["description"]
        )

    print("\n" + "=" * 70)
    print("RISK ANALYSIS")
    print("=" * 70)

    risk = result["risk_analysis"]

    print(
        f"\nOverall Rule Score: "
        f"{risk['overall_rule_score']}/100"
    )

    print(
        f"Credential Risk: "
        f"{risk['credential_risk']}"
    )

    print(
        f"Financial Risk: "
        f"{risk['financial_risk']}"
    )

    print(
        f"Social Engineering Risk: "
        f"{risk['social_engineering_risk']}"
    )

    print(
        f"Link Risk: "
        f"{risk['link_risk']}"
    )

    for category in risk["categories"]:

        print(
            f"\n{category['category']}: "
            f"{category['level']}"
        )

        print(
            category["explanation"]
        )

    print("\n" + "=" * 70)
    print("POTENTIAL IMPACT")
    print("=" * 70)

    for impact in result["potential_impact"]:

        print(
            f"\n[{impact['severity']}] "
            f"{impact['impact']}"
        )

        print(
            impact["description"]
        )

    print("\n" + "=" * 70)
    print("PREVENTION & RECOMMENDATIONS")
    print("=" * 70)

    for recommendation in result["recommendations"]:

        print(
            f"\n[{recommendation['priority']}] "
            f"{recommendation['action']}"
        )

        print(
            f"Reason: "
            f"{recommendation['reason']}"
        )

    print("\n" + "=" * 70)
    print("INCIDENT RESPONSE")
    print("=" * 70)

    for item in result["incident_response"]:

        print(
            f"- {item}"
        )

    print("\n" + "=" * 70)
    print("FINAL SECURITY CONCLUSION")
    print("=" * 70)

    print(
        result["report"]["platform"]
    )

    print(
        result["report"]["report_type"]
    )

    print(
        "\n" + result["report"]["disclaimer"]
    )

    print(
        "\n" + result["analysis_summary"]
    )

    print()
    print("=" * 70)
    print("              ANALYSIS COMPLETE")
    print("=" * 70)