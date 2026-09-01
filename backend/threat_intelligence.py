import os
import csv
import requests
from urllib.parse import urlparse


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

THREAT_DATABASE_PATH = os.path.join(
    BASE_DIR,
    "data",
    "phishtank.csv"
)

REQUEST_TIMEOUT = 8

URLHAUS_API_URL = (
    "https://urlhaus-api.abuse.ch/v1/url/"
)

GOOGLE_SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/"
    "v4/threatMatches:find"
)

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv(
    "GOOGLE_SAFE_BROWSING_API_KEY",
    ""
)


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(url: str) -> str:
    """
    Normalizes a URL for comparison.
    """

    if not isinstance(url, str):
        return ""

    url = url.strip().lower()

    if not url:
        return ""

    if not url.startswith(
        ("http://", "https://")
    ):
        url = "http://" + url

    # Remove trailing slash
    url = url.rstrip("/")

    return url


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain(url: str) -> str:
    """
    Extracts hostname from URL.
    """

    try:

        normalized = normalize_url(
            url
        )

        if not normalized:
            return ""

        parsed = urlparse(
            normalized
        )

        return (
            parsed.hostname or ""
        ).lower()

    except Exception:
        return ""


# ============================================================
# LOAD LOCAL THREAT DATABASE
# ============================================================

def load_threat_database():
    """
    Loads known malicious URLs from the local
    PhishTank CSV database.

    Returns:
        set of normalized malicious URLs
    """

    known_urls = set()

    if not os.path.exists(
        THREAT_DATABASE_PATH
    ):

        print(
            f"Threat database not found: "
            f"{THREAT_DATABASE_PATH}"
        )

        return known_urls

    try:

        with open(
            THREAT_DATABASE_PATH,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            reader = csv.DictReader(
                file
            )

            for row in reader:

                url = (
                    row.get("url")
                    or row.get("URL")
                    or row.get("phish_url")
                    or row.get("phishing_url")
                )

                if url:

                    normalized = normalize_url(
                        url
                    )

                    if normalized:

                        known_urls.add(
                            normalized
                        )

    except Exception as error:

        print(
            f"Error loading threat database: "
            f"{error}"
        )

    print(
        f"Loaded {len(known_urls)} "
        f"known malicious URLs."
    )

    return known_urls


# ============================================================
# LOAD THREAT DATABASE ONCE
# ============================================================

THREAT_DATABASE = (
    load_threat_database()
)


# ============================================================
# EXACT LOCAL DATABASE CHECK
# ============================================================

def check_local_database(
    url: str,
    known_urls=None
) -> dict:
    """
    Checks exact URL against the local
    PhishTank database.
    """

    normalized_url = normalize_url(
        url
    )

    if known_urls is None:

        known_urls = THREAT_DATABASE

    if normalized_url in known_urls:

        return {

            "checked": True,

            "matched": True,

            "status":
                "KNOWN_THREAT",

            "source":
                "PhishTank",

            "reason":
                "URL exists in known phishing records."
        }

    return {

        "checked": True,

        "matched": False,

        "status":
            "NOT_FOUND",

        "source":
            "PhishTank",

        "reason":
            "URL was not found in the local phishing database."
    }


# ============================================================
# URLHAUS LIVE CHECK
# ============================================================

def check_urlhaus(
    url: str
) -> dict:
    """
    Performs a live URLhaus lookup.

    IMPORTANT:
    Not found does NOT mean safe.
    """

    result = {

        "checked": False,

        "matched": False,

        "status":
            "UNKNOWN",

        "source":
            "URLhaus",

        "reason":
            "",

        "threat":
            None,

        "url_status":
            None,

        "tags":
            [],

        "error":
            None
    }

    normalized_url = normalize_url(
        url
    )

    if not normalized_url:

        result["status"] = "INVALID_URL"

        result["reason"] = (
            "Invalid URL."
        )

        return result

    try:

        response = requests.post(

            URLHAUS_API_URL,

            data={
                "url": normalized_url
            },

            timeout=REQUEST_TIMEOUT
        )

        result["checked"] = True

        if response.status_code != 200:

            result["status"] = (
                "SERVICE_ERROR"
            )

            result["reason"] = (
                f"URLhaus returned HTTP "
                f"{response.status_code}."
            )

            return result

        data = response.json()

        query_status = data.get(
            "query_status",
            ""
        )

        # ----------------------------------------------------
        # URL not present
        # ----------------------------------------------------

        if query_status in (
            "no_results",
            "not_found"
        ):

            result["status"] = (
                "NOT_FOUND"
            )

            result["reason"] = (
                "URL was not found in URLhaus."
            )

            return result

        # ----------------------------------------------------
        # Known malicious URL
        # ----------------------------------------------------

        result["matched"] = True

        result["status"] = (
            "KNOWN_THREAT"
        )

        result["reason"] = (
            "URL was found in URLhaus threat intelligence."
        )

        result["threat"] = data.get(
            "threat"
        )

        result["url_status"] = data.get(
            "url_status"
        )

        result["tags"] = data.get(
            "tags"
        ) or []

        return result

    except requests.exceptions.Timeout:

        result["status"] = "TIMEOUT"

        result["reason"] = (
            "URLhaus request timed out."
        )

        result["error"] = (
            "Request timeout."
        )

        return result

    except requests.exceptions.RequestException as error:

        result["status"] = (
            "NETWORK_ERROR"
        )

        result["reason"] = (
            "Unable to connect to URLhaus."
        )

        result["error"] = str(
            error
        )

        return result

    except Exception as error:

        result["status"] = "ERROR"

        result["reason"] = (
            "Unexpected URLhaus error."
        )

        result["error"] = str(
            error
        )

        return result


# ============================================================
# GOOGLE SAFE BROWSING CHECK
# ============================================================

def check_google_safe_browsing(
    url: str
) -> dict:
    """
    Checks the URL against Google Safe Browsing.

    API key is optional.

    Configure it using:

        GOOGLE_SAFE_BROWSING_API_KEY=...

    """

    result = {

        "checked": False,

        "matched": False,

        "status":
            "NOT_CONFIGURED",

        "source":
            "Google Safe Browsing",

        "reason":
            "",

        "threats":
            [],

        "error":
            None
    }

    if not GOOGLE_SAFE_BROWSING_API_KEY:

        result["reason"] = (
            "Google Safe Browsing API key "
            "is not configured."
        )

        return result

    normalized_url = normalize_url(
        url
    )

    if not normalized_url:

        result["status"] = (
            "INVALID_URL"
        )

        result["reason"] = (
            "Invalid URL."
        )

        return result

    payload = {

        "client": {

            "clientId":
                "CyberSentinel",

            "clientVersion":
                "1.0"
        },

        "threatInfo": {

            "threatTypes": [

                "MALWARE",

                "SOCIAL_ENGINEERING",

                "UNWANTED_SOFTWARE",

                "POTENTIALLY_HARMFUL_APPLICATION"
            ],

            "platformTypes": [

                "ANY_PLATFORM"
            ],

            "threatEntryTypes": [

                "URL"
            ],

            "threatEntries": [

                {
                    "url":
                        normalized_url
                }
            ]
        }
    }

    endpoint = (
        GOOGLE_SAFE_BROWSING_URL
        +
        "?key="
        +
        GOOGLE_SAFE_BROWSING_API_KEY
    )

    try:

        response = requests.post(

            endpoint,

            json=payload,

            timeout=REQUEST_TIMEOUT
        )

        result["checked"] = True

        if response.status_code != 200:

            result["status"] = (
                "SERVICE_ERROR"
            )

            result["reason"] = (
                f"Google Safe Browsing returned "
                f"HTTP {response.status_code}."
            )

            return result

        data = response.json()

        matches = data.get(
            "matches",
            []
        )

        if matches:

            result["matched"] = True

            result["status"] = (
                "KNOWN_THREAT"
            )

            result["reason"] = (
                "Google Safe Browsing "
                "reported a threat."
            )

            result["threats"] = [

                {
                    "threatType":
                        match.get(
                            "threatType"
                        ),

                    "platformType":
                        match.get(
                            "platformType"
                        )
                }

                for match in matches
            ]

        else:

            result["status"] = (
                "NOT_FOUND"
            )

            result["reason"] = (
                "No known threat was returned "
                "for this URL."
            )

        return result

    except requests.exceptions.Timeout:

        result["status"] = (
            "TIMEOUT"
        )

        result["reason"] = (
            "Google Safe Browsing request timed out."
        )

        return result

    except requests.exceptions.RequestException as error:

        result["status"] = (
            "NETWORK_ERROR"
        )

        result["reason"] = (
            "Unable to connect to Google Safe Browsing."
        )

        result["error"] = str(
            error
        )

        return result

    except Exception as error:

        result["status"] = (
            "ERROR"
        )

        result["reason"] = (
            "Unexpected Google Safe Browsing error."
        )

        result["error"] = str(
            error
        )

        return result


# ============================================================
# COMBINED THREAT INTELLIGENCE CHECK
# ============================================================

def analyze_threat_intelligence(
    url: str,
    use_live_intelligence: bool = True
) -> dict:
    """
    Performs all available threat-intelligence checks.

    Sources:

        Local PhishTank database
        URLhaus
        Google Safe Browsing

    Returns combined intelligence.
    """

    if not isinstance(
        url,
        str
    ):

        raise ValueError(
            "URL must be a string."
        )

    url = url.strip()

    if not url:

        raise ValueError(
            "URL cannot be empty."
        )

    normalized_url = normalize_url(
        url
    )

    domain = extract_domain(
        normalized_url
    )

    # --------------------------------------------------------
    # LOCAL DATABASE
    # --------------------------------------------------------

    local_result = (
        check_local_database(
            normalized_url
        )
    )

    # --------------------------------------------------------
    # LIVE SOURCES
    # --------------------------------------------------------

    if use_live_intelligence:

        urlhaus_result = (
            check_urlhaus(
                normalized_url
            )
        )

        google_result = (
            check_google_safe_browsing(
                normalized_url
            )
        )

    else:

        urlhaus_result = {

            "checked":
                False,

            "matched":
                False,

            "status":
                "DISABLED",

            "source":
                "URLhaus",

            "reason":
                "Live intelligence disabled."
        }

        google_result = {

            "checked":
                False,

            "matched":
                False,

            "status":
                "DISABLED",

            "source":
                "Google Safe Browsing",

            "reason":
                "Live intelligence disabled."
        }

    # --------------------------------------------------------
    # KNOWN THREAT
    # --------------------------------------------------------

    known_threat = (
        local_result["matched"]
        or
        urlhaus_result["matched"]
        or
        google_result["matched"]
    )

    # --------------------------------------------------------
    # THREAT SCORE
    # --------------------------------------------------------

    threat_score = 0

    if local_result["matched"]:

        threat_score += 70

    if urlhaus_result["matched"]:

        threat_score += 80

    if google_result["matched"]:

        threat_score += 90

    threat_score = min(
        threat_score,
        100
    )

    # --------------------------------------------------------
    # SOURCES
    # --------------------------------------------------------

    matched_sources = []

    if local_result["matched"]:

        matched_sources.append(
            "PhishTank"
        )

    if urlhaus_result["matched"]:

        matched_sources.append(
            "URLhaus"
        )

    if google_result["matched"]:

        matched_sources.append(
            "Google Safe Browsing"
        )

    # --------------------------------------------------------
    # SECURITY SIGNALS
    # --------------------------------------------------------

    signals = []

    if local_result["matched"]:

        signals.append(
            "URL matched a known PhishTank record."
        )

    if urlhaus_result["matched"]:

        signals.append(
            "URL matched the URLhaus threat feed."
        )

    if google_result["matched"]:

        signals.append(
            "Google Safe Browsing reported this URL."
        )

    # --------------------------------------------------------
    # INTELLIGENCE STATUS
    # --------------------------------------------------------
    #
    # IMPORTANT:
    #
    # NOT_FOUND != SAFE
    #
    # It only means that the queried intelligence
    # sources did not know about the URL.
    # --------------------------------------------------------

    if known_threat:

        intelligence_status = (
            "KNOWN_THREAT"
        )

        threat_level = "HIGH"

    elif (
        local_result["checked"]
        or
        urlhaus_result["checked"]
        or
        google_result["checked"]
    ):

        intelligence_status = (
            "NO_KNOWN_THREAT_FOUND"
        )

        threat_level = "LOW"

    else:

        intelligence_status = (
            "INTELLIGENCE_UNAVAILABLE"
        )

        threat_level = "UNKNOWN"

    # --------------------------------------------------------
    # SERVICE INFORMATION
    # --------------------------------------------------------

    services = [

        local_result,

        urlhaus_result,

        google_result
    ]

    checked_services = sum(
        service.get(
            "checked",
            False
        )
        for service in services
    )

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    return {

        "url":
            normalized_url,

        "domain":
            domain,

        "known_threat":
            known_threat,

        "intelligence_status":
            intelligence_status,

        "threat_score":
            threat_score,

        "threat_level":
            threat_level,

        "matched_sources":
            matched_sources,

        "signals":
            signals,

        "checked_services":
            checked_services,

        "local_database":
            local_result,

        "urlhaus":
            urlhaus_result,

        "google_safe_browsing":
            google_result
    }


# ============================================================
# COMPATIBILITY FUNCTION
# ============================================================
#
# Your old code used:
#
#     check_url(url)
#
# Keep this function so existing code does not immediately
# break.
# ============================================================

def check_url(
    url: str,
    known_urls=None
) -> dict:
    """
    Backward-compatible threat check.

    Performs local + live threat intelligence.
    """

    if known_urls is not None:

        local_result = (
            check_local_database(
                url,
                known_urls
            )
        )

        if local_result["matched"]:

            return {

                "matched":
                    True,

                "status":
                    "KNOWN_THREAT",

                "source":
                    "PhishTank",

                "domain":
                    extract_domain(url),

                "reason":
                    local_result[
                        "reason"
                    ]
            }

    result = (
        analyze_threat_intelligence(
            url
        )
    )

    return {

        "matched":
            result[
                "known_threat"
            ],

        "status":
            result[
                "intelligence_status"
            ],

        "source":
            ", ".join(
                result[
                    "matched_sources"
                ]
            )
            if result[
                "matched_sources"
            ]
            else
            "Threat Intelligence",

        "domain":
            result[
                "domain"
            ],

        "reason":
            "; ".join(
                result[
                    "signals"
                ]
            )
            if result[
                "signals"
            ]
            else
            (
                "URL was not found in the "
                "currently checked threat-intelligence sources."
            ),

        "threat_score":
            result[
                "threat_score"
            ]
    }


# ============================================================
# FLAT FEATURES FOR RISK ENGINE
# ============================================================

def get_threat_features(
    url: str
) -> dict:
    """
    Returns simple numerical features that can
    be consumed by risk_engine.py.
    """

    result = (
        analyze_threat_intelligence(
            url
        )
    )

    return {

        "known_threat":
            int(
                result[
                    "known_threat"
                ]
            ),

        "threat_score":
            result[
                "threat_score"
            ],

        "urlhaus_match":
            int(
                result[
                    "urlhaus"
                ][
                    "matched"
                ]
            ),

        "phishtank_match":
            int(
                result[
                    "local_database"
                ][
                    "matched"
                ]
            ),

        "google_safe_browsing_match":
            int(
                result[
                    "google_safe_browsing"
                ][
                    "matched"
                ]
            ),

        "checked_services":
            result[
                "checked_services"
            ]
    }


# ============================================================
# SIMPLE TEST
# ============================================================

def test_threat_intelligence(
    url: str
):

    print()
    print("=" * 70)
    print(
        "CYBERSENTINEL THREAT INTELLIGENCE TEST"
    )
    print("=" * 70)

    print()
    print(
        f"URL: {url}"
    )

    try:

        result = (
            analyze_threat_intelligence(
                url
            )
        )

    except Exception as error:

        print()
        print(
            f"ERROR: {error}"
        )

        return

    print()

    print(
        f"Domain: "
        f"{result['domain']}"
    )

    print(
        f"Intelligence status: "
        f"{result['intelligence_status']}"
    )

    print(
        f"Known threat: "
        f"{result['known_threat']}"
    )

    print(
        f"Threat score: "
        f"{result['threat_score']}/100"
    )

    print(
        f"Threat level: "
        f"{result['threat_level']}"
    )

    print()

    print(
        "Matched sources:"
    )

    if result[
        "matched_sources"
    ]:

        for source in result[
            "matched_sources"
        ]:

            print(
                f"  • {source}"
            )

    else:

        print(
            "  • None"
        )

    print()

    print(
        "Local PhishTank:"
    )

    print(
        f"  Checked: "
        f"{result['local_database']['checked']}"
    )

    print(
        f"  Matched: "
        f"{result['local_database']['matched']}"
    )

    print()

    print(
        "URLhaus:"
    )

    print(
        f"  Checked: "
        f"{result['urlhaus']['checked']}"
    )

    print(
        f"  Matched: "
        f"{result['urlhaus']['matched']}"
    )

    print(
        f"  Status: "
        f"{result['urlhaus']['status']}"
    )

    print()

    print(
        "Google Safe Browsing:"
    )

    print(
        f"  Checked: "
        f"{result['google_safe_browsing']['checked']}"
    )

    print(
        f"  Matched: "
        f"{result['google_safe_browsing']['matched']}"
    )

    print()

    print(
        "Security signals:"
    )

    if result["signals"]:

        for signal in result[
            "signals"
        ]:

            print(
                f"  • {signal}"
            )

    else:

        print(
            "  • No known threat signals."
        )

    print()

    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print(
        "CyberSentinel Threat Intelligence"
    )
    print(
        "================================="
    )

    test_urls = [

        "https://example.com",

        "https://www.google.com",

        "https://www.amazon.in"
    ]

    for url in test_urls:

        test_threat_intelligence(
            url
        )