import re
import math
import ipaddress
from urllib.parse import urlparse, unquote

import tldextract


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "authenticate",
    "authentication",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "password",
    "credential",
    "wallet",
    "bank",
    "banking",
    "payment",
    "refund",
    "otp",
    "bonus",
    "prize",
    "winner",
    "claim",
    "unlock",
    "suspended",
    "suspension",
    "recover",
    "recovery",
    "billing",
    "invoice"
]


# ============================================================
# SUSPICIOUS QUERY PARAMETERS
# ============================================================

SUSPICIOUS_PARAMETERS = [
    "login",
    "signin",
    "username",
    "user",
    "password",
    "passwd",
    "pass",
    "credential",
    "verify",
    "verification",
    "token",
    "otp",
    "pin",
    "payment",
    "card",
    "account",
    "redirect",
    "return",
    "continue",
    "url"
]


# ============================================================
# FEATURE ORDER
#
# IMPORTANT:
# This exact order is used by:
#   1. train_model.py
#   2. ml_model.py
#
# NEVER change the order without retraining the model.
# ============================================================

FEATURE_ORDER = [

    # Original URL features
    "url_length",
    "domain_length",
    "hostname_length",
    "path_length",
    "query_length",

    "dot_count",
    "hyphen_count",
    "underscore_count",
    "slash_count",
    "question_mark_count",
    "equal_count",
    "at_symbol_count",
    "ampersand_count",

    "digit_count",
    "special_character_count",

    "subdomain_length",
    "subdomain_count",

    "uses_https",
    "has_ip_address",

    "suspicious_keyword_count",

    "url_entropy",

    # New generalized features
    "letter_count",
    "digit_ratio",
    "letter_ratio",

    "domain_digit_count",
    "domain_letter_count",
    "domain_hyphen_count",
    "domain_entropy",
    "domain_digit_ratio",

    "subdomain_depth",

    "has_non_standard_port",
    "has_fragment",

    "percent_encoded_count",
    "hex_sequence_count",

    "non_ascii_count",
    "has_punycode",

    "double_slash_count",
    "repeated_character_count",

    "suspicious_parameter_count",
    "query_parameter_count",

    "domain_path_ratio",

    "path_digit_count",
    "path_special_character_count",

    "query_digit_count",
    "query_special_character_count",

    "hostname_entropy",

    "domain_has_numbers",
    "domain_has_hyphen",

    "long_subdomain_flag",
    "long_url_flag",

    "encoded_url_flag",
    "suspicious_port_flag"
]


# ============================================================
# IP ADDRESS CHECK
# ============================================================

def is_ip_address(hostname: str) -> int:

    if not hostname:
        return 0

    try:

        ipaddress.ip_address(hostname)

        return 1

    except ValueError:

        return 0


# ============================================================
# DIGIT COUNT
# ============================================================

def count_digits(text: str) -> int:

    return sum(
        char.isdigit()
        for char in text
    )


# ============================================================
# LETTER COUNT
# ============================================================

def count_letters(text: str) -> int:

    return sum(
        char.isalpha()
        for char in text
    )


# ============================================================
# SPECIAL CHARACTER COUNT
# ============================================================

def count_special_characters(text: str) -> int:

    return len(
        re.findall(
            r"[^a-zA-Z0-9]",
            text
        )
    )


# ============================================================
# NON-ASCII COUNT
# ============================================================

def count_non_ascii(text: str) -> int:

    return sum(
        ord(char) > 127
        for char in text
    )


# ============================================================
# TOKENIZE URL
# ============================================================

def tokenize_url(text: str) -> list:

    return [
        token

        for token in re.split(
            r"[^a-zA-Z0-9]+",
            text.lower()
        )

        if token
    ]


# ============================================================
# SUSPICIOUS KEYWORD COUNT
# ============================================================

def count_suspicious_keywords(url: str) -> int:

    parsed = urlparse(url)

    meaningful_text = " ".join([
        parsed.hostname or "",
        parsed.path or "",
        parsed.query or "",
        parsed.fragment or ""
    ])

    tokens = set(
        tokenize_url(
            meaningful_text
        )
    )

    count = 0

    for keyword in SUSPICIOUS_KEYWORDS:

        keyword_tokens = tokenize_url(
            keyword
        )

        if all(
            token in tokens
            for token in keyword_tokens
        ):

            count += 1

    return count


# ============================================================
# SUSPICIOUS QUERY PARAMETER COUNT
# ============================================================

def count_suspicious_parameters(
    query: str
) -> int:

    if not query:
        return 0

    query_lower = query.lower()

    count = 0

    for parameter in SUSPICIOUS_PARAMETERS:

        if parameter in query_lower:

            count += 1

    return count


# ============================================================
# QUERY PARAMETER COUNT
# ============================================================

def count_query_parameters(
    query: str
) -> int:

    if not query:
        return 0

    parts = re.split(
        r"[&;]",
        query
    )

    return len([
        part
        for part in parts
        if part.strip()
    ])


# ============================================================
# SHANNON ENTROPY
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
# NORMALIZE URL
# ============================================================

def normalize_url(url: str) -> str:

    if url is None:
        return ""

    url = str(
        url
    ).strip()

    if not url:
        return ""

    if not url.lower().startswith(
        (
            "http://",
            "https://"
        )
    ):

        url = "http://" + url

    return url


# ============================================================
# PERCENT ENCODING
# ============================================================

def count_percent_encoded(
    url: str
) -> int:

    return len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )


# ============================================================
# HEX SEQUENCES
# ============================================================

def count_hex_sequences(
    url: str
) -> int:

    return len(
        re.findall(
            r"0x[0-9a-fA-F]+",
            url,
            flags=re.IGNORECASE
        )
    )


# ============================================================
# PUNYCODE
# ============================================================

def has_punycode(
    hostname: str
) -> int:

    if not hostname:
        return 0

    labels = hostname.split(".")

    return int(
        any(
            label.lower().startswith("xn--")
            for label in labels
        )
    )


# ============================================================
# REPEATED CHARACTER COUNT
# ============================================================

def repeated_character_count(
    text: str
) -> int:

    if not text:
        return 0

    matches = re.findall(
        r"(.)\1{2,}",
        text.lower()
    )

    return len(matches)


# ============================================================
# NON-STANDARD PORT
# ============================================================

def has_non_standard_port(
    parsed_url
) -> int:

    try:

        port = parsed_url.port

        if port is None:
            return 0

        return int(
            port not in (
                80,
                443
            )
        )

    except ValueError:

        return 1


# ============================================================
# DOMAIN PATH RATIO
# ============================================================

def calculate_domain_path_ratio(
    domain_length: int,
    path_length: int
) -> float:

    if path_length == 0:

        return float(
            domain_length
        )

    return (
        domain_length /
        path_length
    )


# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

def extract_url_features(
    url: str
) -> dict:

    normalized_url = normalize_url(
        url
    )

    # ========================================================
    # EMPTY URL
    # ========================================================

    if not normalized_url:

        return {
            feature: 0.0
            for feature in FEATURE_ORDER
        }

    # ========================================================
    # PARSE URL
    # ========================================================

    parsed = urlparse(
        normalized_url
    )

    hostname = (
        parsed.hostname or ""
    ).lower()

    path = (
        parsed.path or ""
    )

    query = (
        parsed.query or ""
    )

    fragment = (
        parsed.fragment or ""
    )

    # ========================================================
    # DOMAIN EXTRACTION
    # ========================================================

    extracted = tldextract.extract(
        normalized_url
    )

    domain = (
        extracted.domain or ""
    ).lower()

    subdomain = (
        extracted.subdomain or ""
    ).lower()

    suffix = (
        extracted.suffix or ""
    ).lower()

    # ========================================================
    # URL WITHOUT SCHEME
    # ========================================================

    url_without_scheme = re.sub(
        r"^https?://",
        "",
        normalized_url,
        flags=re.IGNORECASE
    )

    # ========================================================
    # DECODED URL
    # ========================================================

    try:

        decoded_url = unquote(
            normalized_url
        )

    except Exception:

        decoded_url = normalized_url

    # ========================================================
    # BASIC COUNTS
    # ========================================================

    url_length = len(
        normalized_url
    )

    domain_length = len(
        domain
    )

    hostname_length = len(
        hostname
    )

    path_length = len(
        path
    )

    query_length = len(
        query
    )

    # ========================================================
    # CHARACTER COUNTS
    # ========================================================

    digit_count = count_digits(
        url_without_scheme
    )

    letter_count = count_letters(
        url_without_scheme
    )

    special_count = count_special_characters(
        url_without_scheme
    )

    # ========================================================
    # RATIOS
    # ========================================================

    digit_ratio = (
        digit_count / url_length

        if url_length > 0

        else 0.0
    )

    letter_ratio = (
        letter_count / url_length

        if url_length > 0

        else 0.0
    )

    # ========================================================
    # DOMAIN CHARACTER COUNTS
    # ========================================================

    domain_digit_count = count_digits(
        domain
    )

    domain_letter_count = count_letters(
        domain
    )

    domain_hyphen_count = domain.count(
        "-"
    )

    domain_digit_ratio = (

        domain_digit_count /
        domain_length

        if domain_length > 0

        else 0.0
    )

    # ========================================================
    # SUBDOMAIN
    # ========================================================

    if subdomain:

        subdomain_parts = [
            part

            for part in subdomain.split(
                "."
            )

            if part
        ]

        subdomain_count = len(
            subdomain_parts
        )

    else:

        subdomain_count = 0

    # ========================================================
    # DOMAIN FLAGS
    # ========================================================

    domain_has_numbers = int(
        domain_digit_count > 0
    )

    domain_has_hyphen = int(
        domain_hyphen_count > 0
    )

    # ========================================================
    # SECURITY FEATURES
    # ========================================================

    ip_flag = is_ip_address(
        hostname
    )

    https_flag = int(
        parsed.scheme.lower()
        == "https"
    )

    punycode_flag = has_punycode(
        hostname
    )

    non_ascii_count = count_non_ascii(
        normalized_url
    )

    percent_encoded_count = (
        count_percent_encoded(
            normalized_url
        )
    )

    hex_sequence_count = (
        count_hex_sequences(
            normalized_url
        )
    )

    # ========================================================
    # QUERY FEATURES
    # ========================================================

    query_parameter_count = (
        count_query_parameters(
            query
        )
    )

    suspicious_parameter_count = (
        count_suspicious_parameters(
            query
        )
    )

    # ========================================================
    # PATH FEATURES
    # ========================================================

    path_digit_count = count_digits(
        path
    )

    path_special_character_count = (
        count_special_characters(
            path
        )
    )

    # ========================================================
    # QUERY CHARACTER FEATURES
    # ========================================================

    query_digit_count = count_digits(
        query
    )

    query_special_character_count = (
        count_special_characters(
            query
        )
    )

    # ========================================================
    # SLASH ANALYSIS
    # ========================================================

    body_for_slash_check = re.sub(
        r"^https?://",
        "",
        normalized_url,
        flags=re.IGNORECASE
    )

    double_slash_count = (
        body_for_slash_check.count(
            "//"
        )
    )

    # ========================================================
    # REPEATED CHARACTER ANALYSIS
    # ========================================================

    repeated_count = (
        repeated_character_count(
            hostname
        )
    )

    # ========================================================
    # PORT
    # ========================================================

    non_standard_port = (
        has_non_standard_port(
            parsed
        )
    )

    # ========================================================
    # FRAGMENT
    # ========================================================

    fragment_flag = int(
        bool(fragment)
    )

    # ========================================================
    # ENTROPY
    # ========================================================

    url_entropy = calculate_entropy(
        url_without_scheme
    )

    domain_entropy = calculate_entropy(
        domain
    )

    hostname_entropy = calculate_entropy(
        hostname
    )

    # ========================================================
    # DOMAIN / PATH RELATIONSHIP
    # ========================================================

    domain_path_ratio = (
        calculate_domain_path_ratio(
            domain_length,
            path_length
        )
    )

    # ========================================================
    # LENGTH FLAGS
    # ========================================================

    long_subdomain_flag = int(
        len(subdomain) >= 25
    )

    long_url_flag = int(
        url_length >= 100
    )

    # ========================================================
    # ENCODING FLAGS
    # ========================================================

    encoded_url_flag = int(
        percent_encoded_count > 0
        or hex_sequence_count > 0
    )

    suspicious_port_flag = int(
        non_standard_port == 1
    )

    # ========================================================
    # FEATURE DICTIONARY
    # ========================================================

    features = {

        # ----------------------------------------------------
        # ORIGINAL FEATURES
        # ----------------------------------------------------

        "url_length":
            url_length,

        "domain_length":
            domain_length,

        "hostname_length":
            hostname_length,

        "path_length":
            path_length,

        "query_length":
            query_length,

        "dot_count":
            url_without_scheme.count(
                "."
            ),

        "hyphen_count":
            url_without_scheme.count(
                "-"
            ),

        "underscore_count":
            url_without_scheme.count(
                "_"
            ),

        "slash_count":
            url_without_scheme.count(
                "/"
            ),

        "question_mark_count":
            normalized_url.count(
                "?"
            ),

        "equal_count":
            normalized_url.count(
                "="
            ),

        "at_symbol_count":
            normalized_url.count(
                "@"
            ),

        "ampersand_count":
            normalized_url.count(
                "&"
            ),

        "digit_count":
            digit_count,

        "special_character_count":
            special_count,

        "subdomain_length":
            len(subdomain),

        "subdomain_count":
            subdomain_count,

        "uses_https":
            https_flag,

        "has_ip_address":
            ip_flag,

        "suspicious_keyword_count":
            count_suspicious_keywords(
                normalized_url
            ),

        "url_entropy":
            url_entropy,

        # ----------------------------------------------------
        # NEW FEATURES
        # ----------------------------------------------------

        "letter_count":
            letter_count,

        "digit_ratio":
            digit_ratio,

        "letter_ratio":
            letter_ratio,

        "domain_digit_count":
            domain_digit_count,

        "domain_letter_count":
            domain_letter_count,

        "domain_hyphen_count":
            domain_hyphen_count,

        "domain_entropy":
            domain_entropy,

        "domain_digit_ratio":
            domain_digit_ratio,

        "subdomain_depth":
            subdomain_count,

        "has_non_standard_port":
            non_standard_port,

        "has_fragment":
            fragment_flag,

        "percent_encoded_count":
            percent_encoded_count,

        "hex_sequence_count":
            hex_sequence_count,

        "non_ascii_count":
            non_ascii_count,

        "has_punycode":
            punycode_flag,

        "double_slash_count":
            double_slash_count,

        "repeated_character_count":
            repeated_count,

        "suspicious_parameter_count":
            suspicious_parameter_count,

        "query_parameter_count":
            query_parameter_count,

        "domain_path_ratio":
            domain_path_ratio,

        "path_digit_count":
            path_digit_count,

        "path_special_character_count":
            path_special_character_count,

        "query_digit_count":
            query_digit_count,

        "query_special_character_count":
            query_special_character_count,

        "hostname_entropy":
            hostname_entropy,

        "domain_has_numbers":
            domain_has_numbers,

        "domain_has_hyphen":
            domain_has_hyphen,

        "long_subdomain_flag":
            long_subdomain_flag,

        "long_url_flag":
            long_url_flag,

        "encoded_url_flag":
            encoded_url_flag,

        "suspicious_port_flag":
            suspicious_port_flag
    }

    return features


# ============================================================
# FEATURE VECTOR
# ============================================================

def get_feature_vector(
    url: str
) -> list:

    features = extract_url_features(
        url
    )

    return [
        features[name]

        for name in FEATURE_ORDER
    ]


# ============================================================
# FEATURE DESCRIPTION
# ============================================================

def get_feature_description(
    url: str
) -> dict:

    features = extract_url_features(
        url
    )

    return {
        name: features[name]

        for name in FEATURE_ORDER
    }


# ============================================================
# FEATURE COUNT
# ============================================================

def get_feature_count() -> int:

    return len(
        FEATURE_ORDER
    )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_urls = [

        "https://www.google.com/",

        "https://www.amazon.in/",

        "https://www.tiktok.com/",

        "https://tiktok2.com/",

        "https://gooogle.com/",

        "https://amaz0n.com/",

        "https://secure-login-example.com/login?username=x&password=y",

        "http://192.168.1.10/login",

        "https://xn--example-9za.com/",

        "https://example.com/path%20encoded"
    ]

    print()
    print("=" * 70)
    print(
        "CYBERSENTINEL FEATURE EXTRACTOR TEST"
    )
    print("=" * 70)

    print()

    print(
        f"Total features: {get_feature_count()}"
    )

    for url in test_urls:

        print()
        print("-" * 70)

        print(
            f"URL: {url}"
        )

        features = get_feature_description(
            url
        )

        print(
            f"Feature count: {len(features)}"
        )

        print()

        for index, name in enumerate(
            FEATURE_ORDER,
            start=1
        ):

            print(
                f"{index:02d}. "
                f"{name:<35} "
                f"{features[name]}"
            )