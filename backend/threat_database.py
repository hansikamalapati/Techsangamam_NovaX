import os
import pandas as pd


# ============================================================
# CYBERSENTINEL - LOCAL THREAT INTELLIGENCE DATABASE
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "data",
    "phishing_urls.csv"
)


# ============================================================
# LOAD KNOWN PHISHING URLS
# ============================================================

def load_threat_database():

    if not os.path.exists(DATASET_PATH):

        raise FileNotFoundError(
            f"Threat database not found: {DATASET_PATH}"
        )

    df = pd.read_csv(DATASET_PATH)

    if "url" not in df.columns:
        raise ValueError(
            "Dataset does not contain a 'url' column."
        )

    if "label" not in df.columns:
        raise ValueError(
            "Dataset does not contain a 'label' column."
        )

    # label = 1 means phishing
    phishing_df = df[df["label"] == 1]

    phishing_urls = set(
        phishing_df["url"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    return phishing_urls


# ============================================================
# CHECK URL AGAINST KNOWN THREATS
# ============================================================

def check_known_threat(url: str):

    phishing_urls = load_threat_database()

    normalized_url = (
        url.strip()
        .lower()
        .rstrip("/")
    )

    normalized_database = {
        item.rstrip("/")
        for item in phishing_urls
    }

    # Known phishing URL
    if normalized_url in normalized_database:

        return {
            "matched": True,
            "source": "CyberSentinel Local Threat Database",
            "match_type": "Known Phishing URL",
            "message": (
                "This URL matches a known phishing "
                "entry in the threat-intelligence database."
            )
        }

    # URL not found
    return {
        "matched": False,
        "source": None,
        "match_type": "No Known Match",
        "message": (
            "URL was not found in the local "
            "threat-intelligence database."
        )
    }