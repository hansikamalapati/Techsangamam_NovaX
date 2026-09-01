# ============================================================
# CYBERSENTINEL DOMAIN ANALYZER
# ============================================================
#
# Purpose:
# Dynamically analyze domains for:
#
#   1. Domain structure
#   2. Suspicious naming patterns
#   3. Typosquatting
#   4. Brand impersonation
#   5. Punycode / Unicode
#   6. URL obfuscation
#   7. DNS information
#   8. Port information
#   9. TLD risk signals
#
# IMPORTANT:
# This module DOES NOT make the final phishing decision.
#
# Final decision:
#
#       ML MODEL
#           +
#       DOMAIN ANALYSIS
#           +
#       TYPOSQUATTING
#           +
#       THREAT INTELLIGENCE
#           +
#       RISK ENGINE
#
# ============================================================

import re
import math
import socket
import ipaddress

from urllib.parse import urlparse

import tldextract


# ============================================================
# SUSPICIOUS DOMAIN TERMS
# ============================================================

SUSPICIOUS_DOMAIN_TERMS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "confirmation",
    "password",
    "credential",
    "wallet",
    "payment",
    "pay",
    "bank",
    "banking",
    "refund",
    "bonus",
    "prize",
    "winner",
    "reward",
    "claim",
    "unlock",
    "suspended",
    "suspension",
    "recovery",
    "recover",
    "billing",
    "invoice",
    "support",
    "authenticate",
    "authentication",
    "activation",
    "activate",
}


# ============================================================
# HIGH-RISK DOMAIN TERMS
# ============================================================

HIGH_RISK_DOMAIN_TERMS = {
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


# ============================================================
# RISKY TLD SIGNALS
# ============================================================
#
# A risky TLD is ONLY a signal.
# It is NOT proof that a domain is malicious.
#
# ============================================================

RISKY_TLD_PATTERNS = {
    "zip",
    "mov",
    "click",
    "top",
    "xyz",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "buzz",
    "work",
    "fit",
}


# ============================================================
# KNOWN BRAND VOCABULARY
# ============================================================
#
# This is a comparison vocabulary.
#
# It does NOT mean:
#
#     if domain == "something":
#         phishing = True
#
# Instead, the submitted domain is compared dynamically
# against these legitimate brand names.
#
# ============================================================

KNOWN_BRANDS = {
    "google",
    "youtube",
    "facebook",
    "instagram",
    "whatsapp",
    "microsoft",
    "outlook",
    "office",
    "apple",
    "icloud",
    "amazon",
    "netflix",
    "paypal",
    "linkedin",
    "twitter",
    "tiktok",
    "telegram",
    "github",
    "gitlab",
    "dropbox",
    "spotify",
    "steam",
    "discord",
    "zoom",
    "adobe",
    "salesforce",
    "cloudflare",
    "walmart",
    "ebay",
    "reddit",
    "pinterest",
    "snapchat",
    "coinbase",
    "binance",
    "chase",
    "citibank",
    "bankofamerica",
}


# ============================================================
# CHARACTER SUBSTITUTIONS
# ============================================================

COMMON_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
}


# ============================================================
# HOMOGLYPH / LOOK-ALIKE CHARACTERS
# ============================================================

UNICODE_HOMOGLYPHS = {
    "а": "a",
    "с": "c",
    "е": "e",
    "і": "i",
    "о": "o",
    "р": "p",
    "ѕ": "s",
    "х": "x",
    "у": "y",
    "Α": "a",
    "Β": "b",
    "Ε": "e",
    "Η": "h",
    "Ι": "i",
    "Κ": "k",
    "Μ": "m",
    "Ν": "n",
    "Ο": "o",
    "Ρ": "p",
    "Τ": "t",
    "Χ": "x",
    "Υ": "y",
}


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(text: str) -> float:

    if not text:
        return 0.0

    probabilities = [
        text.count(char) / len(text)
        for char in set(text)
    ]

    return -sum(
        probability * math.log2(probability)
        for probability in probabilities
    )


# ============================================================
# IP ADDRESS CHECK
# ============================================================

def is_ip_address(hostname: str) -> bool:

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


# ============================================================
# NORMALIZE HOSTNAME
# ============================================================

def normalize_hostname(hostname: str) -> str:

    if not hostname:
        return ""

    return (
        hostname
        .lower()
        .strip()
        .rstrip(".")
    )


# ============================================================
# NORMALIZE BRAND / DOMAIN
# ============================================================

def normalize_brand_text(text: str) -> str:

    if not text:
        return ""

    text = text.lower().strip()

    for fake, real in COMMON_SUBSTITUTIONS.items():
        text = text.replace(fake, real)

    for fake, real in UNICODE_HOMOGLYPHS.items():
        text = text.replace(fake, real)

    return text


# ============================================================
# EXTRACT DOMAIN INFORMATION
# ============================================================

def extract_domain_information(url: str) -> dict:

    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    normalized_url = url

    if not normalized_url.lower().startswith(
        ("http://", "https://")
    ):
        normalized_url = "http://" + normalized_url

    try:

        parsed = urlparse(
            normalized_url
        )

    except Exception as error:

        raise ValueError(
            f"Invalid URL: {error}"
        )

    hostname = normalize_hostname(
        parsed.hostname or ""
    )

    extracted = tldextract.extract(
        normalized_url
    )

    registered_domain = (
        extracted.domain or ""
    ).lower()

    subdomain = (
        extracted.subdomain or ""
    ).lower()

    suffix = (
        extracted.suffix or ""
    ).lower()

    if registered_domain and suffix:

        full_registered_domain = (
            f"{registered_domain}.{suffix}"
        )

    else:

        full_registered_domain = (
            registered_domain
        )

    try:

        port = parsed.port

    except ValueError:

        port = None

    return {

        "hostname":
            hostname,

        "registered_domain":
            full_registered_domain,

        "domain":
            registered_domain,

        "subdomain":
            subdomain,

        "suffix":
            suffix,

        "scheme":
            parsed.scheme.lower(),

        "path":
            parsed.path or "",

        "query":
            parsed.query or "",

        "fragment":
            parsed.fragment or "",

        "port":
            port,
    }


# ============================================================
# DOMAIN LABELS
# ============================================================

def get_domain_labels(hostname: str) -> list:

    if not hostname:
        return []

    return [
        label
        for label in hostname.split(".")
        if label
    ]


# ============================================================
# CHARACTER COUNTS
# ============================================================

def count_digits(text: str) -> int:

    return sum(
        char.isdigit()
        for char in text
    )


def count_letters(text: str) -> int:

    return sum(
        char.isalpha()
        for char in text
    )


def count_special_characters(text: str) -> int:

    return sum(
        not char.isalnum()
        for char in text
    )


# ============================================================
# REPEATED CHARACTER DETECTION
# ============================================================

def count_repeated_sequences(text: str) -> int:

    if not text:
        return 0

    matches = re.findall(
        r"(.)\1{2,}",
        text.lower()
    )

    return len(matches)


# ============================================================
# SUSPICIOUS TERM COUNT
# ============================================================

def count_suspicious_terms(
    domain_text: str
) -> int:

    if not domain_text:
        return 0

    domain_text = domain_text.lower()

    tokens = {
        token
        for token in re.split(
            r"[^a-zA-Z0-9]+",
            domain_text
        )
        if token
    }

    count = 0

    for term in SUSPICIOUS_DOMAIN_TERMS:

        if term in tokens:

            count += 1

    return count


# ============================================================
# FIND SUSPICIOUS TERMS
# ============================================================

def find_suspicious_terms(
    domain_text: str
) -> list:

    if not domain_text:
        return []

    tokens = {
        token.lower()
        for token in re.split(
            r"[^a-zA-Z0-9]+",
            domain_text
        )
        if token
    }

    return sorted(
        term
        for term in SUSPICIOUS_DOMAIN_TERMS
        if term in tokens
    )


# ============================================================
# PUNYCODE
# ============================================================

def has_punycode(
    hostname: str
) -> bool:

    if not hostname:
        return False

    return any(
        label.lower().startswith("xn--")
        for label in hostname.split(".")
    )


# ============================================================
# NON-ASCII
# ============================================================

def count_non_ascii(
    text: str
) -> int:

    return sum(
        ord(char) > 127
        for char in text
    )


# ============================================================
# RATIOS
# ============================================================

def calculate_digit_ratio(
    domain: str
) -> float:

    if not domain:
        return 0.0

    return (
        count_digits(domain)
        /
        len(domain)
    )


def calculate_letter_ratio(
    domain: str
) -> float:

    if not domain:
        return 0.0

    return (
        count_letters(domain)
        /
        len(domain)
    )


# ============================================================
# LEVENSHTEIN DISTANCE
# ============================================================

def levenshtein_distance(
    first: str,
    second: str
) -> int:

    first = first.lower()
    second = second.lower()

    if first == second:
        return 0

    if not first:
        return len(second)

    if not second:
        return len(first)

    previous_row = list(
        range(
            len(second) + 1
        )
    )

    for i, char1 in enumerate(
        first,
        start=1
    ):

        current_row = [i]

        for j, char2 in enumerate(
            second,
            start=1
        ):

            insert_cost = (
                current_row[j - 1] + 1
            )

            delete_cost = (
                previous_row[j] + 1
            )

            replace_cost = (
                previous_row[j - 1]
                +
                (char1 != char2)
            )

            current_row.append(
                min(
                    insert_cost,
                    delete_cost,
                    replace_cost
                )
            )

        previous_row = current_row

    return previous_row[-1]


# ============================================================
# STRING SIMILARITY
# ============================================================

def string_similarity(
    first: str,
    second: str
) -> float:

    first = first.lower()
    second = second.lower()

    if not first or not second:
        return 0.0

    distance = levenshtein_distance(
        first,
        second
    )

    max_length = max(
        len(first),
        len(second)
    )

    if max_length == 0:
        return 1.0

    return (
        1.0
        -
        (
            distance
            /
            max_length
        )
    )


# ============================================================
# CHARACTER SUBSTITUTION SIMILARITY
# ============================================================

def substitution_similarity(
    domain: str,
    brand: str
) -> float:

    normalized_domain = normalize_brand_text(
        domain
    )

    normalized_brand = normalize_brand_text(
        brand
    )

    return string_similarity(
        normalized_domain,
        normalized_brand
    )


# ============================================================
# ADJACENT TRANSPOSITION
# ============================================================

def has_adjacent_transposition(
    candidate: str,
    target: str
) -> bool:

    candidate = candidate.lower()
    target = target.lower()

    if len(candidate) != len(target):
        return False

    differences = []

    for index in range(
        len(candidate)
    ):

        if candidate[index] != target[index]:

            differences.append(
                index
            )

    if len(differences) != 2:
        return False

    first = differences[0]
    second = differences[1]

    return (
        second == first + 1
        and
        candidate[first] == target[second]
        and
        candidate[second] == target[first]
    )


# ============================================================
# BRAND TOKEN MATCH
# ============================================================

def brand_token_match(
    domain: str,
    brand: str
) -> bool:

    domain = normalize_brand_text(
        domain
    )

    brand = normalize_brand_text(
        brand
    )

    if not domain or not brand:
        return False

    tokens = [
        token
        for token in re.split(
            r"[^a-z0-9]+",
            domain
        )
        if token
    ]

    return brand in tokens


# ============================================================
# BRAND + EXTRA CHARACTER DETECTION
# ============================================================

def detect_brand_with_extra_characters(
    domain: str,
    brand: str
) -> bool:

    domain = normalize_brand_text(
        domain
    )

    brand = normalize_brand_text(
        brand
    )

    if not domain or not brand:
        return False

    if domain == brand:
        return False

    # Example:
    #
    # tiktok2
    # amazon1
    # google-login
    #
    if domain.startswith(brand):

        remaining = domain[
            len(brand):
        ]

        if (
            remaining
            and
            len(remaining) <= 4
            and
            all(
                char.isdigit()
                or
                char == "-"
                for char in remaining
            )
        ):

            return True

    # Example:
    #
    # google-login
    # secure-google
    #

    if (
        brand in domain
        and
        len(domain) <= (
            len(brand) + 20
        )
    ):

        pieces = [
            piece
            for piece in re.split(
                r"[-_.]+",
                domain
            )
            if piece
        ]

        if brand in pieces:
            return True

    return False


# ============================================================
# TYPOSQUATTING ANALYSIS
# ============================================================

def analyze_typosquatting(
    domain: str,
    suffix: str
) -> dict:

    domain = (
        domain or ""
    ).lower().strip()

    suffix = (
        suffix or ""
    ).lower().strip()

    if not domain:

        return {

            "detected":
                False,

            "brand":
                None,

            "similarity":
                0.0,

            "similarity_percent":
                0.0,

            "edit_distance":
                None,

            "method":
                None,

            "score":
                0,
        }

    best_brand = None
    best_similarity = 0.0
    best_distance = None
    best_method = None

    # ========================================================
    # Compare with every known brand
    # ========================================================

    for brand in KNOWN_BRANDS:

        # Avoid unreliable one-character comparisons.
        if len(brand) < 3:
            continue

        # ----------------------------------------------------
        # Exact normalized match
        # ----------------------------------------------------

        if domain == brand:

            return {

                "detected":
                    False,

                "brand":
                    brand,

                "similarity":
                    1.0,

                "similarity_percent":
                    100.0,

                "edit_distance":
                    0,

                "method":
                    "exact_match",

                "score":
                    0,
            }

        # ----------------------------------------------------
        # Normal edit-distance similarity
        # ----------------------------------------------------

        normal_similarity = (
            string_similarity(
                domain,
                brand
            )
        )

        # ----------------------------------------------------
        # Digit / character substitution
        # ----------------------------------------------------

        substitution_score = (
            substitution_similarity(
                domain,
                brand
            )
        )

        # ----------------------------------------------------
        # Unicode normalization
        # ----------------------------------------------------

        unicode_score = (
            string_similarity(
                normalize_brand_text(domain),
                brand
            )
        )

        similarity = max(
            normal_similarity,
            substitution_score,
            unicode_score
        )

        distance = levenshtein_distance(
            domain,
            brand
        )

        method = "edit_distance"

        if substitution_score > normal_similarity:
            method = "character_substitution"

        if unicode_score > similarity:
            method = "unicode_homoglyph"

        # ----------------------------------------------------
        # Adjacent transposition
        # ----------------------------------------------------

        if has_adjacent_transposition(
            domain,
            brand
        ):

            similarity = max(
                similarity,
                0.90
            )

            method = (
                "adjacent_transposition"
            )

        # ----------------------------------------------------
        # Brand + extra characters
        # ----------------------------------------------------

        if detect_brand_with_extra_characters(
            domain,
            brand
        ):

            similarity = max(
                similarity,
                0.82
            )

            method = (
                "brand_with_extra_characters"
            )

        # ----------------------------------------------------
        # Brand token
        # ----------------------------------------------------

        if brand_token_match(
            domain,
            brand
        ):

            similarity = max(
                similarity,
                0.85
            )

            method = "brand_token"

        # ----------------------------------------------------
        # Save best result
        # ----------------------------------------------------

        if similarity > best_similarity:

            best_similarity = similarity
            best_brand = brand
            best_distance = distance
            best_method = method

    # ========================================================
    # DETECTION
    # ========================================================

    detected = False
    score = 0

    # --------------------------------------------------------
    # Very close brand
    # --------------------------------------------------------

    if (
        best_similarity >= 0.90
        and
        best_distance is not None
        and
        best_distance <= 2
    ):

        detected = True
        score = 85

    # --------------------------------------------------------
    # Close brand
    # --------------------------------------------------------

    elif (
        best_similarity >= 0.82
        and
        best_distance is not None
        and
        best_distance <= 3
    ):

        detected = True
        score = 70

    # --------------------------------------------------------
    # Brand + suspicious modification
    # --------------------------------------------------------

    elif (
        best_similarity >= 0.80
        and
        best_method
        in {
            "character_substitution",
            "unicode_homoglyph",
            "adjacent_transposition",
            "brand_with_extra_characters",
            "brand_token",
        }
    ):

        detected = True
        score = 70

    # --------------------------------------------------------
    # Suspicious TLD + close brand
    # --------------------------------------------------------

    if (
        best_similarity >= 0.80
        and
        suffix in RISKY_TLD_PATTERNS
    ):

        detected = True

        score = max(
            score,
            72
        )

    return {

        "detected":
            detected,

        "brand":
            best_brand,

        "similarity":
            round(
                best_similarity,
                4
            ),

        "similarity_percent":
            round(
                best_similarity * 100,
                2
            ),

        "edit_distance":
            best_distance,

        "method":
            best_method,

        "score":
            min(
                score,
                100
            ),
    }


# ============================================================
# DOMAIN STRUCTURE
# ============================================================

def analyze_domain_structure(
    hostname: str,
    domain: str,
    subdomain: str,
    suffix: str
) -> dict:

    labels = get_domain_labels(
        hostname
    )

    subdomain_labels = (
        get_domain_labels(
            subdomain
        )
    )

    domain_length = len(
        domain
    )

    hostname_length = len(
        hostname
    )

    suspicious_terms = (
        find_suspicious_terms(
            domain
        )
    )

    return {

        "hostname_length":
            hostname_length,

        "domain_length":
            domain_length,

        "subdomain_length":
            len(subdomain),

        "subdomain_depth":
            len(subdomain_labels),

        "hostname_label_count":
            len(labels),

        "domain_digit_count":
            count_digits(domain),

        "domain_letter_count":
            count_letters(domain),

        "domain_special_character_count":
            count_special_characters(
                domain
            ),

        "domain_digit_ratio":
            calculate_digit_ratio(
                domain
            ),

        "domain_letter_ratio":
            calculate_letter_ratio(
                domain
            ),

        "domain_entropy":
            calculate_entropy(
                domain
            ),

        "hostname_entropy":
            calculate_entropy(
                hostname
            ),

        "hyphen_count":
            domain.count("-"),

        "underscore_count":
            domain.count("_"),

        "dot_count":
            hostname.count("."),

        "repeated_sequence_count":
            count_repeated_sequences(
                domain
            ),

        "suspicious_term_count":
            len(suspicious_terms),

        "suspicious_terms":
            suspicious_terms,

        "high_risk_term_count":
            sum(
                term in HIGH_RISK_DOMAIN_TERMS
                for term in suspicious_terms
            ),

        "has_punycode":
            int(
                has_punycode(
                    hostname
                )
            ),

        "non_ascii_count":
            count_non_ascii(
                hostname
            ),

        "has_numbers":
            int(
                count_digits(domain) > 0
            ),

        "has_hyphen":
            int(
                "-" in domain
            ),

        "long_domain":
            int(
                domain_length >= 25
            ),

        "very_long_domain":
            int(
                domain_length >= 40
            ),

        "long_subdomain":
            int(
                len(subdomain) >= 25
            ),

        "deep_subdomain":
            int(
                len(subdomain_labels) >= 3
            ),
    }


# ============================================================
# TLD ANALYSIS
# ============================================================

def analyze_tld(
    suffix: str
) -> dict:

    suffix = (
        suffix or ""
    ).lower()

    return {

        "tld":
            suffix,

        "tld_length":
            len(suffix),

        "tld_is_present":
            int(
                bool(suffix)
            ),

        "tld_risk_signal":
            int(
                suffix in RISKY_TLD_PATTERNS
            ),
    }


# ============================================================
# SCHEME ANALYSIS
# ============================================================

def analyze_scheme(
    scheme: str
) -> dict:

    scheme = (
        scheme or ""
    ).lower()

    return {

        "uses_https":
            int(
                scheme == "https"
            ),

        "uses_http":
            int(
                scheme == "http"
            ),
    }


# ============================================================
# PORT ANALYSIS
# ============================================================

def analyze_port(
    port
) -> dict:

    if port is None:

        return {

            "has_port":
                0,

            "port":
                None,

            "non_standard_port":
                0,
        }

    standard_ports = {
        80,
        443,
    }

    return {

        "has_port":
            1,

        "port":
            port,

        "non_standard_port":
            int(
                port not in standard_ports
            ),
    }


# ============================================================
# PATH ANALYSIS
# ============================================================

def analyze_path(
    path: str
) -> dict:

    path = path or ""

    path_lower = path.lower()

    security_terms = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "credential",
        "secure",
        "payment",
        "bank",
        "wallet",
        "otp",
        "unlock",
    ]

    matched_terms = [
        term
        for term in security_terms
        if term in path_lower
    ]

    return {

        "path_length":
            len(path),

        "path_digit_count":
            count_digits(path),

        "path_special_character_count":
            count_special_characters(
                path
            ),

        "path_entropy":
            calculate_entropy(
                path
            ),

        "path_has_login_term":
            int(
                bool(matched_terms)
            ),

        "path_security_terms":
            matched_terms,

        "path_has_double_slash":
            int(
                "//" in path
            ),
    }


# ============================================================
# QUERY ANALYSIS
# ============================================================

def analyze_query(
    query: str
) -> dict:

    query = query or ""

    if not query:

        return {

            "query_length":
                0,

            "query_parameter_count":
                0,

            "query_digit_count":
                0,

            "query_special_character_count":
                0,

            "query_entropy":
                0.0,
        }

    parameters = [
        item
        for item in re.split(
            r"[&;]",
            query
        )
        if item
    ]

    return {

        "query_length":
            len(query),

        "query_parameter_count":
            len(parameters),

        "query_digit_count":
            count_digits(query),

        "query_special_character_count":
            count_special_characters(
                query
            ),

        "query_entropy":
            calculate_entropy(
                query
            ),
    }


# ============================================================
# DNS RESOLUTION
# ============================================================

def resolve_domain(
    hostname: str
) -> dict:

    if not hostname:

        return {

            "dns_resolves":
                False,

            "resolved_ips":
                [],

            "ip_count":
                0,

            "dns_error":
                "Hostname is empty.",
        }

    if is_ip_address(
        hostname
    ):

        return {

            "dns_resolves":
                True,

            "resolved_ips":
                [hostname],

            "ip_count":
                1,

            "dns_error":
                None,
        }

    try:

        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        resolved_ips = sorted(
            {
                result[4][0]
                for result in results
                if result[4]
            }
        )

        return {

            "dns_resolves":
                bool(resolved_ips),

            "resolved_ips":
                resolved_ips,

            "ip_count":
                len(resolved_ips),

            "dns_error":
                None,
        }

    except socket.gaierror as error:

        return {

            "dns_resolves":
                False,

            "resolved_ips":
                [],

            "ip_count":
                0,

            "dns_error":
                str(error),
        }

    except Exception as error:

        return {

            "dns_resolves":
                False,

            "resolved_ips":
                [],

            "ip_count":
                0,

            "dns_error":
                str(error),
        }


# ============================================================
# RESOLVED IP ANALYSIS
# ============================================================

def analyze_resolved_ips(
    resolved_ips: list
) -> dict:

    private_count = 0
    loopback_count = 0
    reserved_count = 0
    multicast_count = 0

    for ip_text in resolved_ips:

        try:

            address = ipaddress.ip_address(
                ip_text
            )

            if address.is_private:
                private_count += 1

            if address.is_loopback:
                loopback_count += 1

            if address.is_reserved:
                reserved_count += 1

            if address.is_multicast:
                multicast_count += 1

        except ValueError:

            continue

    return {

        "private_ip_count":
            private_count,

        "loopback_ip_count":
            loopback_count,

        "reserved_ip_count":
            reserved_count,

        "multicast_ip_count":
            multicast_count,

        "has_private_ip":
            int(
                private_count > 0
            ),

        "has_loopback_ip":
            int(
                loopback_count > 0
            ),

        "has_reserved_ip":
            int(
                reserved_count > 0
            ),

        "has_multicast_ip":
            int(
                multicast_count > 0
            ),
    }


# ============================================================
# OBFUSCATION ANALYSIS
# ============================================================

def analyze_obfuscation(
    url: str,
    hostname: str
) -> dict:

    url = url or ""

    without_scheme = re.sub(
        r"^https?://",
        "",
        url,
        flags=re.IGNORECASE,
    )

    has_userinfo = int(
        "@" in without_scheme
    )

    double_slash_count = (
        without_scheme.count("//")
    )

    encoded_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url,
        )
    )

    hex_count = len(
        re.findall(
            r"0x[0-9a-fA-F]+",
            url,
            flags=re.IGNORECASE,
        )
    )

    non_ascii = count_non_ascii(
        url
    )

    backslash_count = url.count(
        "\\"
    )

    return {

        "has_userinfo":
            has_userinfo,

        "double_slash_count":
            double_slash_count,

        "percent_encoded_count":
            encoded_count,

        "hex_sequence_count":
            hex_count,

        "non_ascii_count":
            non_ascii,

        "backslash_count":
            backslash_count,

        "obfuscation_signal":
            int(
                has_userinfo
                or
                encoded_count >= 3
                or
                hex_count > 0
                or
                non_ascii > 0
                or
                backslash_count > 0
            ),
    }


# ============================================================
# SECURITY SIGNAL GENERATION
# ============================================================

def generate_domain_signals(
    url: str,
    information: dict,
    structure: dict,
    tld_analysis: dict,
    port_analysis: dict,
    path_analysis: dict,
    obfuscation_analysis: dict,
    dns_analysis: dict,
    ip_analysis: dict,
    typosquatting: dict,
) -> list:

    signals = []

    hostname = information[
        "hostname"
    ]

    # ========================================================
    # IP ADDRESS
    # ========================================================

    if is_ip_address(
        hostname
    ):

        signals.append(
            "Domain is represented directly by an IP address."
        )

    # ========================================================
    # PUNYCODE
    # ========================================================

    if structure[
        "has_punycode"
    ]:

        signals.append(
            "Domain contains Punycode."
        )

    # ========================================================
    # NON ASCII
    # ========================================================

    if structure[
        "non_ascii_count"
    ] > 0:

        signals.append(
            "Domain contains non-ASCII characters."
        )

    # ========================================================
    # DEEP SUBDOMAIN
    # ========================================================

    if structure[
        "subdomain_depth"
    ] >= 3:

        signals.append(
            "Domain contains multiple subdomain levels."
        )

    # ========================================================
    # LONG SUBDOMAIN
    # ========================================================

    if structure[
        "long_subdomain"
    ]:

        signals.append(
            "Subdomain is unusually long."
        )

    # ========================================================
    # LONG DOMAIN
    # ========================================================

    if structure[
        "long_domain"
    ]:

        signals.append(
            "Registered domain is unusually long."
        )

    # ========================================================
    # SUSPICIOUS TERMS
    # ========================================================

    suspicious_terms = (
        structure.get(
            "suspicious_terms",
            []
        )
    )

    if suspicious_terms:

        signals.append(
            "Security-sensitive domain terms detected: "
            +
            ", ".join(
                suspicious_terms
            )
            +
            "."
        )

    # ========================================================
    # NUMBERS
    # ========================================================

    if structure[
        "domain_digit_ratio"
    ] >= 0.30:

        signals.append(
            "Domain contains a relatively high proportion of digits."
        )

    # ========================================================
    # REPEATED CHARACTERS
    # ========================================================

    if structure[
        "repeated_sequence_count"
    ] > 0:

        signals.append(
            "Domain contains repeated character sequences."
        )

    # ========================================================
    # TLD
    # ========================================================

    if tld_analysis[
        "tld_risk_signal"
    ]:

        signals.append(
            "Top-level domain is associated with elevated abuse risk."
        )

    # ========================================================
    # PORT
    # ========================================================

    if port_analysis[
        "non_standard_port"
    ]:

        signals.append(
            "URL uses a non-standard network port."
        )

    # ========================================================
    # OBFUSCATION
    # ========================================================

    if obfuscation_analysis[
        "obfuscation_signal"
    ]:

        signals.append(
            "URL contains possible obfuscation indicators."
        )

    # ========================================================
    # DNS
    # ========================================================

    if (
        dns_analysis[
            "dns_resolves"
        ]
        is False
    ):

        signals.append(
            "Domain did not successfully resolve through DNS."
        )

    # ========================================================
    # PRIVATE IP
    # ========================================================

    if ip_analysis[
        "has_private_ip"
    ]:

        signals.append(
            "Domain resolves to a private IP address."
        )

    # ========================================================
    # LOOPBACK
    # ========================================================

    if ip_analysis[
        "has_loopback_ip"
    ]:

        signals.append(
            "Domain resolves to a loopback IP address."
        )

    # ========================================================
    # TYPOSQUATTING
    # ========================================================

    if typosquatting[
        "detected"
    ]:

        brand = (
            typosquatting[
                "brand"
            ]
            or
            "known brand"
        )

        similarity = (
            typosquatting[
                "similarity_percent"
            ]
        )

        method = (
            typosquatting[
                "method"
            ]
            or
            "similarity analysis"
        )

        signals.append(
            f"Domain is highly similar to "
            f"'{brand}' "
            f"({similarity}% similarity) "
            f"using "
            f"{method.replace('_', ' ')}."
        )

    return signals


# ============================================================
# DOMAIN SIGNAL SCORE
# ============================================================

def calculate_domain_signal_score(
    information: dict,
    structure: dict,
    tld_analysis: dict,
    port_analysis: dict,
    obfuscation_analysis: dict,
    dns_analysis: dict,
    ip_analysis: dict,
    typosquatting: dict,
) -> int:

    score = 0

    # ========================================================
    # IP ADDRESS
    # ========================================================

    if is_ip_address(
        information[
            "hostname"
        ]
    ):

        score += 18

    # ========================================================
    # PUNYCODE
    # ========================================================

    if structure[
        "has_punycode"
    ]:

        score += 15

    # ========================================================
    # NON ASCII
    # ========================================================

    if structure[
        "non_ascii_count"
    ] > 0:

        score += 12

    # ========================================================
    # DEEP SUBDOMAIN
    # ========================================================

    if structure[
        "subdomain_depth"
    ] >= 4:

        score += 12

    elif structure[
        "subdomain_depth"
    ] >= 3:

        score += 8

    # ========================================================
    # LONG SUBDOMAIN
    # ========================================================

    if structure[
        "long_subdomain"
    ]:

        score += 7

    # ========================================================
    # LONG DOMAIN
    # ========================================================

    if structure[
        "very_long_domain"
    ]:

        score += 10

    elif structure[
        "long_domain"
    ]:

        score += 5

    # ========================================================
    # HYPHENS
    # ========================================================

    if structure[
        "hyphen_count"
    ] >= 5:

        score += 10

    elif structure[
        "hyphen_count"
    ] >= 3:

        score += 6

    # ========================================================
    # DIGITS
    # ========================================================

    if structure[
        "domain_digit_ratio"
    ] >= 0.50:

        score += 12

    elif structure[
        "domain_digit_ratio"
    ] >= 0.30:

        score += 8

    # ========================================================
    # SUSPICIOUS TERMS
    # ========================================================

    suspicious_count = (
        structure[
            "suspicious_term_count"
        ]
    )

    high_risk_count = (
        structure[
            "high_risk_term_count"
        ]
    )

    if high_risk_count >= 2:

        score += 18

    elif high_risk_count == 1:

        score += 10

    if suspicious_count >= 3:

        score += 12

    elif suspicious_count >= 1:

        score += 5

    # ========================================================
    # REPEATED SEQUENCES
    # ========================================================

    if structure[
        "repeated_sequence_count"
    ] > 0:

        score += 5

    # ========================================================
    # TLD
    # ========================================================

    if tld_analysis[
        "tld_risk_signal"
    ]:

        score += 7

    # ========================================================
    # NON STANDARD PORT
    # ========================================================

    if port_analysis[
        "non_standard_port"
    ]:

        score += 8

    # ========================================================
    # OBFUSCATION
    # ========================================================

    if obfuscation_analysis[
        "obfuscation_signal"
    ]:

        score += 10

    # ========================================================
    # DNS FAILURE
    # ========================================================
    #
    # DNS failure is only a weak signal because:
    #
    # - domains can be temporarily unavailable
    # - DNS can be blocked
    # - network connectivity can fail
    #
    # ========================================================

    if (
        dns_analysis[
            "dns_resolves"
        ]
        is False
    ):

        score += 5

    # ========================================================
    # PRIVATE IP
    # ========================================================

    if ip_analysis[
        "has_private_ip"
    ]:

        score += 10

    # ========================================================
    # LOOPBACK
    # ========================================================

    if ip_analysis[
        "has_loopback_ip"
    ]:

        score += 15

    # ========================================================
    # TYPOSQUATTING
    # ========================================================

    score += int(
        typosquatting.get(
            "score",
            0
        )
    )

    return min(
        score,
        100
    )


# ============================================================
# MAIN DOMAIN ANALYSIS
# ============================================================

def analyze_domain(
    url: str,
    perform_dns: bool = True
) -> dict:

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

    # ========================================================
    # DOMAIN INFORMATION
    # ========================================================

    information = (
        extract_domain_information(
            url
        )
    )

    hostname = information[
        "hostname"
    ]

    domain = information[
        "domain"
    ]

    subdomain = information[
        "subdomain"
    ]

    suffix = information[
        "suffix"
    ]

    # ========================================================
    # IP CHECK
    # ========================================================

    ip_address_flag = is_ip_address(
        hostname
    )

    # ========================================================
    # STRUCTURE
    # ========================================================

    structure = (
        analyze_domain_structure(
            hostname,
            domain,
            subdomain,
            suffix
        )
    )

    # ========================================================
    # TLD
    # ========================================================

    tld_analysis = analyze_tld(
        suffix
    )

    # ========================================================
    # SCHEME
    # ========================================================

    scheme_analysis = analyze_scheme(
        information[
            "scheme"
        ]
    )

    # ========================================================
    # PORT
    # ========================================================

    port_analysis = analyze_port(
        information[
            "port"
        ]
    )

    # ========================================================
    # PATH
    # ========================================================

    path_analysis = analyze_path(
        information[
            "path"
        ]
    )

    # ========================================================
    # QUERY
    # ========================================================

    query_analysis = analyze_query(
        information[
            "query"
        ]
    )

    # ========================================================
    # OBFUSCATION
    # ========================================================

    obfuscation_analysis = (
        analyze_obfuscation(
            url,
            hostname
        )
    )

    # ========================================================
    # TYPOSQUATTING
    # ========================================================

    typosquatting = (
        analyze_typosquatting(
            domain,
            suffix
        )
    )

    # ========================================================
    # DNS
    # ========================================================

    if perform_dns:

        dns_analysis = resolve_domain(
            hostname
        )

    else:

        dns_analysis = {

            "dns_resolves":
                None,

            "resolved_ips":
                [],

            "ip_count":
                0,

            "dns_error":
                None,
        }

    # ========================================================
    # RESOLVED IP
    # ========================================================

    ip_analysis = (
        analyze_resolved_ips(
            dns_analysis[
                "resolved_ips"
            ]
        )
    )

    # ========================================================
    # SECURITY SIGNALS
    # ========================================================

    signals = generate_domain_signals(

        url=url,

        information=information,

        structure=structure,

        tld_analysis=tld_analysis,

        port_analysis=port_analysis,

        path_analysis=path_analysis,

        obfuscation_analysis=(
            obfuscation_analysis
        ),

        dns_analysis=dns_analysis,

        ip_analysis=ip_analysis,

        typosquatting=typosquatting,
    )

    # ========================================================
    # DOMAIN SIGNAL SCORE
    # ========================================================

    domain_signal_score = (
        calculate_domain_signal_score(

            information=information,

            structure=structure,

            tld_analysis=tld_analysis,

            port_analysis=port_analysis,

            obfuscation_analysis=(
                obfuscation_analysis
            ),

            dns_analysis=dns_analysis,

            ip_analysis=ip_analysis,

            typosquatting=typosquatting,
        )
    )

    # ========================================================
    # DOMAIN RISK LEVEL
    # ========================================================

    if domain_signal_score >= 70:

        domain_risk_level = "HIGH"

    elif domain_signal_score >= 40:

        domain_risk_level = "MEDIUM"

    else:

        domain_risk_level = "LOW"

    # ========================================================
    # RETURN
    # ========================================================

    return {

        # ----------------------------------------------------
        # BASIC
        # ----------------------------------------------------

        "url":
            url,

        "hostname":
            hostname,

        "registered_domain":
            information[
                "registered_domain"
            ],

        "domain":
            domain,

        "subdomain":
            subdomain,

        "suffix":
            suffix,

        "scheme":
            information[
                "scheme"
            ],

        "port":
            information[
                "port"
            ],

        # ----------------------------------------------------
        # DOMAIN ANALYSIS
        # ----------------------------------------------------

        "domain_analysis":
            structure,

        # ----------------------------------------------------
        # TLD
        # ----------------------------------------------------

        "tld_analysis":
            tld_analysis,

        # ----------------------------------------------------
        # SCHEME
        # ----------------------------------------------------

        "scheme_analysis":
            scheme_analysis,

        # ----------------------------------------------------
        # PORT
        # ----------------------------------------------------

        "port_analysis":
            port_analysis,

        # ----------------------------------------------------
        # PATH
        # ----------------------------------------------------

        "path_analysis":
            path_analysis,

        # ----------------------------------------------------
        # QUERY
        # ----------------------------------------------------

        "query_analysis":
            query_analysis,

        # ----------------------------------------------------
        # OBFUSCATION
        # ----------------------------------------------------

        "obfuscation_analysis":
            obfuscation_analysis,

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------

        "dns_analysis":
            dns_analysis,

        # ----------------------------------------------------
        # IP
        # ----------------------------------------------------

        "ip_analysis":
            ip_analysis,

        # ----------------------------------------------------
        # FLAGS
        # ----------------------------------------------------

        "is_ip_address":
            int(
                ip_address_flag
            ),

        # ----------------------------------------------------
        # TYPOSQUATTING
        # ----------------------------------------------------

        "typosquatting":
            typosquatting,

        "typosquatting_detected":
            bool(
                typosquatting[
                    "detected"
                ]
            ),

        "typosquatting_score":
            typosquatting[
                "score"
            ],

        "impersonated_brand":
            typosquatting[
                "brand"
            ],

        # ----------------------------------------------------
        # SECURITY SIGNALS
        # ----------------------------------------------------

        "signals":
            signals,

        "signal_count":
            len(signals),

        # ----------------------------------------------------
        # FINAL DOMAIN SCORE
        # ----------------------------------------------------

        "domain_signal_score":
            domain_signal_score,

        "domain_risk_level":
            domain_risk_level,
    }


# ============================================================
# FLAT FEATURES FOR ML
# ============================================================

def get_domain_features(
    url: str,
    perform_dns: bool = True
) -> dict:

    result = analyze_domain(
        url,
        perform_dns=perform_dns
    )

    domain_analysis = result[
        "domain_analysis"
    ]

    tld_analysis = result[
        "tld_analysis"
    ]

    scheme_analysis = result[
        "scheme_analysis"
    ]

    port_analysis = result[
        "port_analysis"
    ]

    path_analysis = result[
        "path_analysis"
    ]

    query_analysis = result[
        "query_analysis"
    ]

    obfuscation_analysis = result[
        "obfuscation_analysis"
    ]

    dns_analysis = result[
        "dns_analysis"
    ]

    ip_analysis = result[
        "ip_analysis"
    ]

    typosquatting = result[
        "typosquatting"
    ]

    return {

        # ====================================================
        # DOMAIN
        # ====================================================

        "domain_length":
            domain_analysis[
                "domain_length"
            ],

        "hostname_length":
            domain_analysis[
                "hostname_length"
            ],

        "subdomain_length":
            domain_analysis[
                "subdomain_length"
            ],

        "subdomain_depth":
            domain_analysis[
                "subdomain_depth"
            ],

        "hostname_label_count":
            domain_analysis[
                "hostname_label_count"
            ],

        # ====================================================
        # CHARACTERS
        # ====================================================

        "domain_digit_count":
            domain_analysis[
                "domain_digit_count"
            ],

        "domain_letter_count":
            domain_analysis[
                "domain_letter_count"
            ],

        "domain_special_character_count":
            domain_analysis[
                "domain_special_character_count"
            ],

        "domain_digit_ratio":
            domain_analysis[
                "domain_digit_ratio"
            ],

        "domain_letter_ratio":
            domain_analysis[
                "domain_letter_ratio"
            ],

        # ====================================================
        # ENTROPY
        # ====================================================

        "domain_entropy":
            domain_analysis[
                "domain_entropy"
            ],

        "hostname_entropy":
            domain_analysis[
                "hostname_entropy"
            ],

        # ====================================================
        # STRUCTURE
        # ====================================================

        "hyphen_count":
            domain_analysis[
                "hyphen_count"
            ],

        "underscore_count":
            domain_analysis[
                "underscore_count"
            ],

        "dot_count":
            domain_analysis[
                "dot_count"
            ],

        "repeated_sequence_count":
            domain_analysis[
                "repeated_sequence_count"
            ],

        # ====================================================
        # SUSPICIOUS TERMS
        # ====================================================

        "suspicious_term_count":
            domain_analysis[
                "suspicious_term_count"
            ],

        "high_risk_term_count":
            domain_analysis[
                "high_risk_term_count"
            ],

        # ====================================================
        # PUNYCODE / UNICODE
        # ====================================================

        "has_punycode":
            domain_analysis[
                "has_punycode"
            ],

        "non_ascii_count":
            domain_analysis[
                "non_ascii_count"
            ],

        # ====================================================
        # BOOLEAN FEATURES
        # ====================================================

        "has_numbers":
            domain_analysis[
                "has_numbers"
            ],

        "has_hyphen":
            domain_analysis[
                "has_hyphen"
            ],

        "long_domain":
            domain_analysis[
                "long_domain"
            ],

        "very_long_domain":
            domain_analysis[
                "very_long_domain"
            ],

        "long_subdomain":
            domain_analysis[
                "long_subdomain"
            ],

        "deep_subdomain":
            domain_analysis[
                "deep_subdomain"
            ],

        # ====================================================
        # TLD
        # ====================================================

        "tld_risk_signal":
            tld_analysis[
                "tld_risk_signal"
            ],

        # ====================================================
        # HTTP / HTTPS
        # ====================================================

        "uses_https":
            scheme_analysis[
                "uses_https"
            ],

        "uses_http":
            scheme_analysis[
                "uses_http"
            ],

        # ====================================================
        # PORT
        # ====================================================

        "has_port":
            port_analysis[
                "has_port"
            ],

        "non_standard_port":
            port_analysis[
                "non_standard_port"
            ],

        # ====================================================
        # PATH
        # ====================================================

        "path_length":
            path_analysis[
                "path_length"
            ],

        "path_entropy":
            path_analysis[
                "path_entropy"
            ],

        "path_has_login_term":
            path_analysis[
                "path_has_login_term"
            ],

        # ====================================================
        # QUERY
        # ====================================================

        "query_length":
            query_analysis[
                "query_length"
            ],

        "query_parameter_count":
            query_analysis[
                "query_parameter_count"
            ],

        "query_entropy":
            query_analysis[
                "query_entropy"
            ],

        # ====================================================
        # OBFUSCATION
        # ====================================================

        "has_userinfo":
            obfuscation_analysis[
                "has_userinfo"
            ],

        "percent_encoded_count":
            obfuscation_analysis[
                "percent_encoded_count"
            ],

        "hex_sequence_count":
            obfuscation_analysis[
                "hex_sequence_count"
            ],

        "obfuscation_signal":
            obfuscation_analysis[
                "obfuscation_signal"
            ],

        # ====================================================
        # DNS
        # ====================================================

        "dns_resolves":
            int(
                bool(
                    dns_analysis[
                        "dns_resolves"
                    ]
                )
            ),

        "resolved_ip_count":
            dns_analysis[
                "ip_count"
            ],

        # ====================================================
        # IP
        # ====================================================

        "has_private_ip":
            ip_analysis[
                "has_private_ip"
            ],

        "has_loopback_ip":
            ip_analysis[
                "has_loopback_ip"
            ],

        # ====================================================
        # TYPOSQUATTING
        # ====================================================

        "typosquatting_detected":
            int(
                typosquatting[
                    "detected"
                ]
            ),

        "typosquatting_score":
            typosquatting[
                "score"
            ],

        "brand_similarity":
            typosquatting[
                "similarity"
            ],

        "brand_edit_distance":
            (
                typosquatting[
                    "edit_distance"
                ]
                if
                typosquatting[
                    "edit_distance"
                ] is not None
                else 0
            ),

        # ====================================================
        # FINAL DOMAIN SCORE
        # ====================================================

        "domain_signal_score":
            result[
                "domain_signal_score"
            ],
    }


# ============================================================
# SIMPLE TEST FUNCTION
# ============================================================

def test_domain(
    url: str
):

    print()
    print("=" * 75)
    print(
        "CYBERSENTINEL DOMAIN ANALYZER"
    )
    print("=" * 75)

    print(
        f"\nURL: {url}"
    )

    try:

        result = analyze_domain(
            url
        )

    except Exception as error:

        print(
            f"Analysis failed: {error}"
        )

        return

    print(
        f"\nHostname: "
        f"{result['hostname']}"
    )

    print(
        f"Registered domain: "
        f"{result['registered_domain']}"
    )

    print(
        f"Domain: "
        f"{result['domain']}"
    )

    print(
        f"Subdomain: "
        f"{result['subdomain']}"
    )

    print(
        f"TLD: "
        f"{result['suffix']}"
    )

    print(
        f"HTTPS: "
        f"{result['scheme_analysis']['uses_https']}"
    )

    print(
        f"IP address: "
        f"{result['is_ip_address']}"
    )

    print(
        f"DNS resolves: "
        f"{result['dns_analysis']['dns_resolves']}"
    )

    # ========================================================
    # TYPOSQUATTING
    # ========================================================

    typo = result[
        "typosquatting"
    ]

    print(
        "\nTyposquatting Analysis:"
    )

    print(
        f"  Detected: "
        f"{typo['detected']}"
    )

    print(
        f"  Closest brand: "
        f"{typo['brand']}"
    )

    print(
        f"  Similarity: "
        f"{typo['similarity_percent']}%"
    )

    print(
        f"  Edit distance: "
        f"{typo['edit_distance']}"
    )

    print(
        f"  Method: "
        f"{typo['method']}"
    )

    print(
        f"  Typosquatting score: "
        f"{typo['score']}/100"
    )

    # ========================================================
    # DOMAIN RISK
    # ========================================================

    print(
        f"\nDomain signal score: "
        f"{result['domain_signal_score']}/100"
    )

    print(
        f"Domain risk level: "
        f"{result['domain_risk_level']}"
    )

    # ========================================================
    # SECURITY SIGNALS
    # ========================================================

    print(
        "\nSecurity signals:"
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
            "  • No significant domain signals detected."
        )

    print(
        "\n" + "=" * 75
    )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    test_urls = [

        # ----------------------------------------------------
        # Normal domains
        # ----------------------------------------------------

        "https://www.google.com",

        "https://www.amazon.in",

        "https://www.tiktok.com",

        # ----------------------------------------------------
        # Brand modification
        # ----------------------------------------------------

        "https://tiktok2.com",

        "https://gooogle.com",

        "https://amaz0n.com",

        "https://paypa1.com",

        "https://micros0ft.com",

        # ----------------------------------------------------
        # Suspicious URL
        # ----------------------------------------------------

        "https://secure-login-example.com/login",

        # ----------------------------------------------------
        # IP URL
        # ----------------------------------------------------

        "http://192.168.1.10/login",
    ]

    for url in test_urls:

        test_domain(
            url
        )