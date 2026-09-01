# ============================================================
# CYBERSENTINEL - IMAGE / SCREENSHOT ANALYZER
# ============================================================

import re

import pytesseract
from PIL import Image

from message_analyzer import analyze_message_rules


# ============================================================
# TESSERACT CONFIGURATION
# ============================================================

# Tesseract OCR installation path
TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls_from_text(text: str):
    """
    Extracts HTTP and HTTPS URLs from OCR text.
    """

    if not text:
        return []

    pattern = r"https?://[^\s]+"

    urls = re.findall(
        pattern,
        text
    )

    # Remove common punctuation accidentally captured by OCR
    cleaned_urls = []

    for url in urls:

        url = url.rstrip(
            ".,;:!?)]}>\"'"
        )

        cleaned_urls.append(url)

    return cleaned_urls


# ============================================================
# POSSIBLE DOMAIN / URL DETECTION
# ============================================================

def extract_possible_domains(text: str):
    """
    Detects domain-like strings from OCR text.

    This helps when OCR does not capture the
    http:// or https:// part.
    """

    if not text:
        return []

    pattern = (
        r"\b(?:www\.)?"
        r"[a-zA-Z0-9-]+"
        r"\."
        r"[a-zA-Z]{2,}"
        r"(?:/[^\s]*)?"
    )

    matches = re.findall(
        pattern,
        text
    )

    domains = []

    for item in matches:

        item = item.rstrip(
            ".,;:!?)]}>\"'"
        )

        # Avoid duplicates
        if item not in domains:
            domains.append(item)

    return domains


# ============================================================
# OCR TEXT EXTRACTION
# ============================================================

def extract_text_from_image(image_path: str):
    """
    Extracts text from an image using Tesseract OCR.
    """

    try:

        image = Image.open(
            image_path
        )

        # Convert image to RGB
        image = image.convert(
            "RGB"
        )

        text = pytesseract.image_to_string(
            image
        )

        return text.strip()

    except Exception as error:

        raise RuntimeError(
            f"OCR failed: {str(error)}"
        )


# ============================================================
# OCR ENGINE TEST
# ============================================================

def test_ocr_engine():
    """
    Checks whether Tesseract OCR is available.
    """

    try:

        version = (
            pytesseract
            .get_tesseract_version()
        )

        return {
            "available": True,
            "version": str(version)
        }

    except Exception as error:

        return {
            "available": False,
            "version": None,
            "error": str(error)
        }


# ============================================================
# IMAGE ANALYSIS
# ============================================================

def analyze_image(image_path: str):
    """
    Performs complete screenshot analysis.

    Processing pipeline:

        Screenshot
             ↓
        Tesseract OCR
             ↓
        Extracted Text
             ↓
        URL Detection
             ↓
        Message Rule Analysis
             ↓
        Social Engineering Indicators
    """

    # --------------------------------------------------------
    # STEP 1: OCR
    # --------------------------------------------------------

    extracted_text = extract_text_from_image(
        image_path
    )

    # --------------------------------------------------------
    # STEP 2: URL EXTRACTION
    # --------------------------------------------------------

    urls = extract_urls_from_text(
        extracted_text
    )

    # --------------------------------------------------------
    # STEP 3: POSSIBLE DOMAIN EXTRACTION
    # --------------------------------------------------------

    possible_domains = extract_possible_domains(
        extracted_text
    )

    # --------------------------------------------------------
    # STEP 4: MESSAGE ANALYSIS
    # --------------------------------------------------------

    if extracted_text:

        message_analysis = analyze_message_rules(
            extracted_text
        )

    else:

        message_analysis = {
            "rule_score": 0,
            "threat_type": "No Text Detected",
            "indicators": [],
            "features": {}
        }

    # --------------------------------------------------------
    # STEP 5: DETERMINE IMAGE VERDICT
    # --------------------------------------------------------

    rule_score = message_analysis[
        "rule_score"
    ]

    threat_type = message_analysis[
        "threat_type"
    ]

    # Basic image-level verdict
    if rule_score >= 70:

        verdict = "PHISHING"

    elif rule_score >= 40:

        verdict = "SUSPICIOUS"

    else:

        verdict = "LEGITIMATE"

    # --------------------------------------------------------
    # STEP 6: RECOMMENDATION
    # --------------------------------------------------------

    if verdict == "PHISHING":

        recommendation = (
            "High-risk phishing or social-engineering "
            "indicators were detected in the screenshot. "
            "Do not click links or provide sensitive "
            "information."
        )

    elif verdict == "SUSPICIOUS":

        recommendation = (
            "Suspicious social-engineering indicators "
            "were detected. Verify the message through "
            "an official source before taking action."
        )

    else:

        recommendation = (
            "No strong phishing indicators were detected "
            "in the extracted text. Continue to use normal "
            "security precautions."
        )

    # --------------------------------------------------------
    # STEP 7: FINAL RESULT
    # --------------------------------------------------------

    return {

        "extracted_text":
            extracted_text,

        "ocr_success":
            bool(extracted_text),

        "urls_found":
            urls,

        "url_count":
            len(urls),

        "possible_domains":
            possible_domains,

        "domain_count":
            len(possible_domains),

        "detection": {

            "verdict":
                verdict,

            "risk_score":
                rule_score,

            "threat_type":
                threat_type
        },

        "security_analysis": {

            "rule_score":
                message_analysis[
                    "rule_score"
                ],

            "indicators":
                message_analysis[
                    "indicators"
                ],

            "features":
                message_analysis[
                    "features"
                ]
        },

        "recommendation":
            recommendation
    }


# ============================================================
# TEST IMAGE ANALYZER
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("       CYBERSENTINEL IMAGE ANALYZER")
    print("=" * 60)

    print()
    print("OCR Engine: Tesseract")

    # --------------------------------------------------------
    # TEST TESSERACT
    # --------------------------------------------------------

    print()
    print("Checking Tesseract...")

    ocr_status = test_ocr_engine()

    if ocr_status["available"]:

        print(
            "Tesseract Status : READY"
        )

        print(
            "Tesseract Version:",
            ocr_status["version"]
        )

    else:

        print(
            "Tesseract Status : NOT AVAILABLE"
        )

        print(
            "Error:",
            ocr_status["error"]
        )

    print()
    print("=" * 60)

    print()
    print("Image analyzer module loaded successfully.")

    print()
    print("Ready to analyze screenshots.")