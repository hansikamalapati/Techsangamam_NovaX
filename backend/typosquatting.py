import os
import re
import csv
import math
from functools import lru_cache
from urllib.parse import urlparse

import tldextract


# ============================================================
# CYBERSENTINEL TYPOSQUATTING ANALYZER
# ============================================================
#
# Purpose:
# Detect domains that may imitate legitimate domains.
#
# Example:
#
#     amazon.com
#     amaz0n.com
#
#     google.com
#     gooogle.com
#
#     paypal.com
#     paypa1.com
#
# IMPORTANT:
#
# No specific phishing domain is hardcoded.
#
# Legitimate reference domains are loaded dynamically from:
#
#     data/phishing_urls.csv
#
# where:
#
#     label = 0  -> legitimate
#     label = 1  -> phishing
#
# ============================================================


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "data",
    "phishing_urls.csv"
)


# ============================================================
# CONFIGURATION
# ============================================================

# Only compare domains that are reasonably similar in length.
MAX_LENGTH_DIFFERENCE = 4

# Similarity above this value is considered interesting.
SIMILARITY_THRESHOLD = 0.72

# Strong similarity threshold.
HIGH_SIMILARITY_THRESHOLD = 0.88

# Maximum number of reference domains returned.
MAX_MATCHES = 10


# ============================================================
# COMMON CHARACTER SUBSTITUTIONS
# ============================================================
#
# These are generic character-confusion signals.
# They are not website-specific.
# ============================================================

CHARACTER_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g"
}


# ============================================================
# HOMOGLYPH GROUPS
# ============================================================
#
# Used for detecting visually similar characters.
# ============================================================

HOMOGLYPH_GROUPS = [
    {"a", "ɑ"},
    {"c", "с"},
    {"e", "е"},
    {"i", "і"},
    {"j", "ј"},
    {"o", "о"},
    {"p", "р"},
    {"s", "ѕ"},
    {"x", "х"},
    {"y", "у"},
    {"v", "ν"},
]


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_registered_domain(url: str) -> str:
    """
    Extracts the registered domain from a URL.

    Example:

        https://login.example.com/account

    becomes:

        example.com
    """

    if not isinstance(url, str):
        return ""

    url = url.strip()

    if not url:
        return ""

    if not url.lower().startswith(
        ("http://", "https://")
    ):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = (
        parsed.hostname or ""
    ).lower()

    if not hostname:
        return ""

    extracted = tldextract.extract(
        hostname
    )

    domain = (
        extracted.domain or ""
    )

    suffix = (
        extracted.suffix or ""
    )

    if domain and suffix:
        return f"{domain}.{suffix}"

    return domain


# ============================================================
# DOMAIN CORE
# ============================================================

def get_domain_core(
    registered_domain: str
) -> str:

    if not registered_domain:
        return ""

    extracted = tldextract.extract(
        registered_domain
    )

    return (
        extracted.domain or ""
    ).lower()


# ============================================================
# NORMALIZE DOMAIN
# ============================================================

def normalize_domain(
    domain: str
) -> str:

    if not domain:
        return ""

    domain = domain.lower()

    # Remove everything except letters,
    # numbers and hyphens.
    domain = re.sub(
        r"[^a-z0-9-]",
        "",
        domain
    )

    return domain


# ============================================================
# CHARACTER NORMALIZATION
# ============================================================

def normalize_confusable_characters(
    text: str
) -> str:

    if not text:
        return ""

    result = []

    for char in text.lower():

        if char in CHARACTER_SUBSTITUTIONS:

            result.append(
                CHARACTER_SUBSTITUTIONS[
                    char
                ]
            )

        else:

            result.append(
                char
            )

    return "".join(result)


# ============================================================
# LEVENSHTEIN DISTANCE
# ============================================================

@lru_cache(maxsize=50000)
def levenshtein_distance(
    first: str,
    second: str
) -> int:

    """
    Calculates edit distance.

    Operations:

        insertion
        deletion
        substitution
    """

    if first == second:
        return 0

    if not first:
        return len(second)

    if not second:
        return len(first)

    # Keep second string shorter for
    # lower memory consumption.
    if len(first) < len(second):

        first, second = (
            second,
            first
        )

    previous = list(
        range(
            len(second) + 1
        )
    )

    for i, char_first in enumerate(
        first,
        start=1
    ):

        current = [
            i
        ]

        for j, char_second in enumerate(
            second,
            start=1
        ):

            insertion = (
                current[j - 1] + 1
            )

            deletion = (
                previous[j] + 1
            )

            substitution = (
                previous[j - 1]
                +
                (
                    0
                    if char_first == char_second
                    else 1
                )
            )

            current.append(
                min(
                    insertion,
                    deletion,
                    substitution
                )
            )

        previous = current

    return previous[-1]


# ============================================================
# SIMILARITY
# ============================================================

def calculate_similarity(
    first: str,
    second: str
) -> float:

    first = normalize_domain(
        first
    )

    second = normalize_domain(
        second
    )

    if not first or not second:
        return 0.0

    if first == second:
        return 1.0

    max_length = max(
        len(first),
        len(second)
    )

    distance = levenshtein_distance(
        first,
        second
    )

    return max(
        0.0,
        1.0 -
        (
            distance /
            max_length
        )
    )


# ============================================================
# PREFIX / SUFFIX SIMILARITY
# ============================================================

def common_prefix_length(
    first: str,
    second: str
) -> int:

    count = 0

    for a, b in zip(
        first,
        second
    ):

        if a != b:
            break

        count += 1

    return count


def common_suffix_length(
    first: str,
    second: str
) -> int:

    count = 0

    for a, b in zip(
        reversed(first),
        reversed(second)
    ):

        if a != b:
            break

        count += 1

    return count


# ============================================================
# CHARACTER CONFUSION SCORE
# ============================================================

def calculate_confusion_score(
    domain: str
) -> float:

    if not domain:
        return 0.0

    domain = domain.lower()

    substitutions = 0

    for char in domain:

        if char in CHARACTER_SUBSTITUTIONS:

            substitutions += 1

    if substitutions == 0:
        return 0.0

    return min(
        1.0,
        substitutions /
        max(1, len(domain))
    )


# ============================================================
# REPEATED CHARACTER CHECK
# ============================================================

def repeated_character_score(
    domain: str
) -> float:

    if not domain:
        return 0.0

    repeated = re.findall(
        r"(.)\1+",
        domain.lower()
    )

    if not repeated:
        return 0.0

    return min(
        1.0,
        len(repeated) /
        max(1, len(domain))
    )


# ============================================================
# CHARACTER INSERTION / DELETION SIGNAL
# ============================================================

def detect_single_edit_pattern(
    domain: str,
    reference: str
) -> bool:

    domain = normalize_domain(
        domain
    )

    reference = normalize_domain(
        reference
    )

    if not domain or not reference:
        return False

    distance = levenshtein_distance(
        domain,
        reference
    )

    return distance == 1


# ============================================================
# LOAD LEGITIMATE DOMAINS
# ============================================================

def load_legitimate_domains(
    dataset_path: str = DATASET_PATH
) -> list:

    """
    Loads legitimate domains from the dataset.

    Expected columns:

        url
        label
        source

    Expected labels:

        0 = legitimate
        1 = phishing
    """

    domains = set()

    if not os.path.exists(
        dataset_path
    ):

        print(
            "Warning: phishing_urls.csv "
            "was not found."
        )

        return []

    try:

        with open(
            dataset_path,
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
                    or
                    row.get("URL")
                    or
                    ""
                )

                label = (
                    row.get("label")
                    or
                    row.get("Label")
                    or
                    ""
                )

                try:

                    label_value = int(
                        float(label)
                    )

                except (
                    ValueError,
                    TypeError
                ):

                    continue

                # 0 = legitimate
                if label_value != 0:
                    continue

                registered_domain = (
                    extract_registered_domain(
                        url
                    )
                )

                core = get_domain_core(
                    registered_domain
                )

                core = normalize_domain(
                    core
                )

                if core:

                    domains.add(
                        core
                    )

    except Exception as error:

        print(
            "Could not load legitimate "
            f"domains: {error}"
        )

        return []

    return sorted(
        domains
    )


# ============================================================
# CACHE LEGITIMATE DOMAINS
# ============================================================

@lru_cache(maxsize=1)
def get_reference_domains() -> tuple:

    return tuple(
        load_legitimate_domains()
    )


# ============================================================
# FIND SIMILAR LEGITIMATE DOMAINS
# ============================================================

def find_similar_domains(
    domain_core: str,
    reference_domains: list | tuple
) -> list:

    if not domain_core:

        return []

    domain_core = normalize_domain(
        domain_core
    )

    if not domain_core:

        return []

    candidates = []

    domain_length = len(
        domain_core
    )

    for reference in reference_domains:

        reference = normalize_domain(
            reference
        )

        if not reference:
            continue

        if reference == domain_core:
            continue

        # Ignore obviously unrelated lengths.
        if abs(
            len(reference)
            -
            domain_length
        ) > MAX_LENGTH_DIFFERENCE:

            continue

        similarity = calculate_similarity(
            domain_core,
            reference
        )

        if similarity < SIMILARITY_THRESHOLD:
            continue

        prefix = common_prefix_length(
            domain_core,
            reference
        )

        suffix = common_suffix_length(
            domain_core,
            reference
        )

        candidates.append({

            "reference_domain":
                reference,

            "similarity":
                round(
                    similarity,
                    4
                ),

            "edit_distance":
                levenshtein_distance(
                    domain_core,
                    reference
                ),

            "common_prefix":
                prefix,

            "common_suffix":
                suffix,

            "single_edit":
                detect_single_edit_pattern(
                    domain_core,
                    reference
                )
        })

    candidates.sort(
        key=lambda item:
        item["similarity"],
        reverse=True
    )

    return candidates[
        :MAX_MATCHES
    ]


# ============================================================
# VISUAL SIMILARITY
# ============================================================

def visual_similarity(
    domain: str,
    reference: str
) -> float:

    domain_normalized = (
        normalize_confusable_characters(
            domain
        )
    )

    reference_normalized = (
        normalize_confusable_characters(
            reference
        )
    )

    return calculate_similarity(
        domain_normalized,
        reference_normalized
    )


# ============================================================
# FIND VISUALLY SIMILAR DOMAINS
# ============================================================

def find_visual_matches(
    domain_core: str,
    reference_domains: list | tuple
) -> list:

    if not domain_core:
        return []

    domain_core = normalize_domain(
        domain_core
    )

    results = []

    for reference in reference_domains:

        reference = normalize_domain(
            reference
        )

        if not reference:
            continue

        if reference == domain_core:
            continue

        if abs(
            len(reference)
            -
            len(domain_core)
        ) > MAX_LENGTH_DIFFERENCE:

            continue

        similarity = visual_similarity(
            domain_core,
            reference
        )

        if similarity >= HIGH_SIMILARITY_THRESHOLD:

            results.append({

                "reference_domain":
                    reference,

                "visual_similarity":
                    round(
                        similarity,
                        4
                    ),

                "edit_distance":
                    levenshtein_distance(
                        domain_core,
                        reference
                    )
            })

    results.sort(
        key=lambda item:
        item["visual_similarity"],
        reverse=True
    )

    return results[
        :MAX_MATCHES
    ]


# ============================================================
# GENERIC TYPOSQUATTING SIGNALS
# ============================================================

def calculate_generic_signals(
    domain_core: str
) -> dict:

    domain_core = normalize_domain(
        domain_core
    )

    if not domain_core:

        return {

            "digit_count": 0,

            "digit_substitution_count": 0,

            "digit_substitution_ratio": 0.0,

            "repeated_character_count": 0,

            "hyphen_count": 0,

            "double_hyphen": 0,

            "very_short_domain": 0,

            "very_long_domain": 0
        }

    digit_count = sum(
        char.isdigit()
        for char in domain_core
    )

    substitution_count = sum(
        char in CHARACTER_SUBSTITUTIONS
        for char in domain_core
    )

    repeated_count = len(
        re.findall(
            r"(.)\1+",
            domain_core
        )
    )

    return {

        "digit_count":
            digit_count,

        "digit_substitution_count":
            substitution_count,

        "digit_substitution_ratio":
            round(
                substitution_count /
                max(1, len(domain_core)),
                4
            ),

        "repeated_character_count":
            repeated_count,

        "hyphen_count":
            domain_core.count("-"),

        "double_hyphen":
            int(
                "--" in domain_core
            ),

        "very_short_domain":
            int(
                len(domain_core) <= 3
            ),

        "very_long_domain":
            int(
                len(domain_core) >= 30
            )
    }


# ============================================================
# TYPOSQUATTING SCORE
# ============================================================

def calculate_typosquatting_score(
    similar_domains: list,
    visual_matches: list,
    generic_signals: dict
) -> int:

    score = 0

    # --------------------------------------------------------
    # Strong domain similarity
    # --------------------------------------------------------

    if similar_domains:

        best_similarity = (
            similar_domains[0][
                "similarity"
            ]
        )

        if best_similarity >= 0.95:

            score += 60

        elif best_similarity >= 0.88:

            score += 45

        elif best_similarity >= 0.80:

            score += 30

        elif best_similarity >= 0.72:

            score += 15

    # --------------------------------------------------------
    # Visual similarity
    # --------------------------------------------------------

    if visual_matches:

        best_visual = (
            visual_matches[0][
                "visual_similarity"
            ]
        )

        if best_visual >= 0.95:

            score += 25

        elif best_visual >= 0.88:

            score += 18

        elif best_visual >= 0.80:

            score += 10

    # --------------------------------------------------------
    # Numeric substitutions
    # --------------------------------------------------------

    if (
        generic_signals[
            "digit_substitution_count"
        ] > 0
    ):

        score += 10

    # --------------------------------------------------------
    # Repeated characters
    # --------------------------------------------------------

    if (
        generic_signals[
            "repeated_character_count"
        ] > 0
    ):

        score += 5

    # --------------------------------------------------------
    # Clamp
    # --------------------------------------------------------

    return min(
        100,
        score
    )


# ============================================================
# MAIN ANALYSIS
# ============================================================

def analyze_typosquatting(
    url: str,
    reference_domains=None
) -> dict:

    """
    Dynamically analyzes whether a domain
    resembles legitimate domains.

    No website-specific phishing rules
    are used.
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

    # --------------------------------------------------------
    # Extract domain
    # --------------------------------------------------------

    registered_domain = (
        extract_registered_domain(
            url
        )
    )

    domain_core = (
        get_domain_core(
            registered_domain
        )
    )

    domain_core = normalize_domain(
        domain_core
    )

    if reference_domains is None:

        reference_domains = (
            get_reference_domains()
        )

    # --------------------------------------------------------
    # Generic signals
    # --------------------------------------------------------

    generic_signals = (
        calculate_generic_signals(
            domain_core
        )
    )

    # --------------------------------------------------------
    # Similarity search
    # --------------------------------------------------------

    similar_domains = (
        find_similar_domains(
            domain_core,
            reference_domains
        )
    )

    # --------------------------------------------------------
    # Visual matches
    # --------------------------------------------------------

    visual_matches = (
        find_visual_matches(
            domain_core,
            reference_domains
        )
    )

    # --------------------------------------------------------
    # Exact legitimate domain check
    # --------------------------------------------------------

    exact_legitimate_match = (
        domain_core in
        set(reference_domains)
    )

    # --------------------------------------------------------
    # Score
    # --------------------------------------------------------

    score = (
        calculate_typosquatting_score(
            similar_domains,
            visual_matches,
            generic_signals
        )
    )

    # --------------------------------------------------------
    # Signals
    # --------------------------------------------------------

    signals = []

    if exact_legitimate_match:

        signals.append(
            "Domain exactly matches a legitimate reference domain."
        )

    if similar_domains:

        best = similar_domains[0]

        signals.append(
            "Domain is similar to legitimate "
            f"reference domain "
            f"'{best['reference_domain']}' "
            f"with similarity "
            f"{best['similarity'] * 100:.1f}%."
        )

    if visual_matches:

        best_visual = (
            visual_matches[0]
        )

        signals.append(
            "Domain has high visual similarity "
            f"to '{best_visual['reference_domain']}'."
        )

    if (
        generic_signals[
            "digit_substitution_count"
        ] > 0
    ):

        signals.append(
            "Domain contains numeric character substitution signals."
        )

    if (
        generic_signals[
            "repeated_character_count"
        ] > 0
    ):

        signals.append(
            "Domain contains repeated characters."
        )

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    if exact_legitimate_match:

        risk_level = "LOW"

    elif score >= 70:

        risk_level = "HIGH"

    elif score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {

        "url":
            url,

        "registered_domain":
            registered_domain,

        "domain_core":
            domain_core,

        "reference_domain_count":
            len(reference_domains),

        "exact_legitimate_match":
            exact_legitimate_match,

        "similar_domains":
            similar_domains,

        "visual_matches":
            visual_matches,

        "generic_signals":
            generic_signals,

        "typosquatting_score":
            score,

        "typosquatting_risk_level":
            risk_level,

        "signals":
            signals
    }


# ============================================================
# SIMPLE TEST FUNCTION
# ============================================================

def test_typosquatting(
    url: str
):

    print()
    print("=" * 70)
    print(
        "CYBERSENTINEL TYPOSQUATTING ANALYZER"
    )
    print("=" * 70)

    print()
    print(
        f"URL: {url}"
    )

    try:

        result = analyze_typosquatting(
            url
        )

    except Exception as error:

        print()
        print(
            f"Analysis failed: {error}"
        )

        return

    print()

    print(
        f"Registered domain: "
        f"{result['registered_domain']}"
    )

    print(
        f"Domain core: "
        f"{result['domain_core']}"
    )

    print(
        f"Reference domains: "
        f"{result['reference_domain_count']}"
    )

    print(
        f"Typosquatting score: "
        f"{result['typosquatting_score']}/100"
    )

    print(
        f"Risk level: "
        f"{result['typosquatting_risk_level']}"
    )

    print()

    print(
        "Closest legitimate domains:"
    )

    if result["similar_domains"]:

        for match in result[
            "similar_domains"
        ]:

            print(
                f"  • "
                f"{match['reference_domain']} "
                f"→ "
                f"{match['similarity'] * 100:.2f}% "
                f"similar"
            )

    else:

        print(
            "  • No strong matches found."
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
            "  • No typosquatting signals detected."
        )

    print()

    print("=" * 70)


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    test_urls = [

        "https://www.google.com",

        "https://www.amazon.in",

        "https://www.tiktok.com",

        "https://tiktok2.com",

        "https://amaz0n.com",

        "https://gooogle.com",

        "https://paypa1.com",

        "https://secure-login-example.com"
    ]

    for test_url in test_urls:

        test_typosquatting(
            test_url
        )