# ============================================================
# CYBERSENTINEL - WEB APPLICATION SECURITY SCANNER
# Passive security analysis only
# ============================================================

import socket
import ssl
from urllib.parse import urlparse

import requests


USER_AGENT = (
    "CyberSentinel-Security-Scanner/1.0 "
    "(defensive security assessment)"
)

TIMEOUT = 8


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_target(url: str) -> str:

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


# ============================================================
# SECURITY HEADERS
# ============================================================

SECURITY_HEADERS = {
    "strict-transport-security":
        "HSTS",

    "content-security-policy":
        "Content Security Policy",

    "x-content-type-options":
        "X-Content-Type-Options",

    "x-frame-options":
        "Clickjacking Protection",

    "referrer-policy":
        "Referrer Policy",

    "permissions-policy":
        "Permissions Policy"
}


# ============================================================
# COOKIE ANALYSIS
# ============================================================

def analyze_cookies(response):

    findings = []

    cookies = response.headers.get("set-cookie", "")

    if not cookies:
        return findings

    cookie_text = cookies.lower()

    if "secure" not in cookie_text:
        findings.append({
            "type": "Cookie Security",
            "severity": "MEDIUM",
            "finding": "Cookie without Secure attribute."
        })

    if "httponly" not in cookie_text:
        findings.append({
            "type": "Cookie Security",
            "severity": "MEDIUM",
            "finding": "Cookie without HttpOnly attribute."
        })

    if "samesite" not in cookie_text:
        findings.append({
            "type": "Cookie Security",
            "severity": "LOW",
            "finding": "Cookie without SameSite attribute."
        })

    return findings


# ============================================================
# SECURITY HEADER ANALYSIS
# ============================================================

def analyze_security_headers(response):

    findings = []

    headers = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    for header, description in SECURITY_HEADERS.items():

        if header not in headers:

            severity = "MEDIUM"

            if header in (
                "strict-transport-security",
                "content-security-policy"
            ):
                severity = "HIGH"

            findings.append({
                "type": "Security Header",
                "severity": severity,
                "finding": f"Missing {description}."
            })

    return findings


# ============================================================
# SERVER INFORMATION
# ============================================================

def analyze_server_information(response):

    findings = []

    server = response.headers.get("server")

    if server:

        findings.append({
            "type": "Information Disclosure",
            "severity": "LOW",
            "finding": f"Server header exposed: {server}"
        })

    powered_by = response.headers.get("x-powered-by")

    if powered_by:

        findings.append({
            "type": "Information Disclosure",
            "severity": "LOW",
            "finding": (
                f"Technology information exposed: "
                f"{powered_by}"
            )
        })

    return findings


# ============================================================
# CORS ANALYSIS
# ============================================================

def analyze_cors(response):

    findings = []

    allow_origin = response.headers.get(
        "access-control-allow-origin"
    )

    if allow_origin == "*":

        findings.append({
            "type": "CORS",
            "severity": "MEDIUM",
            "finding": (
                "Access-Control-Allow-Origin is configured "
                "with wildcard '*'."
            )
        })

    return findings


# ============================================================
# HTTPS ANALYSIS
# ============================================================

def analyze_transport(url):

    findings = []

    parsed = urlparse(url)

    if parsed.scheme != "https":

        findings.append({
            "type": "Transport Security",
            "severity": "HIGH",
            "finding": "Application is not using HTTPS."
        })

    return findings


# ============================================================
# DNS INFORMATION
# ============================================================

def analyze_dns(hostname):

    result = {
        "resolved": False,
        "ip_addresses": []
    }

    if not hostname:
        return result

    try:

        addresses = socket.getaddrinfo(
            hostname,
            None
        )

        ips = sorted({
            item[4][0]
            for item in addresses
        })

        result["resolved"] = bool(ips)
        result["ip_addresses"] = ips

    except Exception:
        pass

    return result


# ============================================================
# REDIRECT ANALYSIS
# ============================================================

def analyze_redirects(response, original_url):

    findings = []

    final_url = response.url

    original_host = urlparse(
        original_url
    ).hostname

    final_host = urlparse(
        final_url
    ).hostname

    if (
        original_host
        and final_host
        and original_host.lower()
        != final_host.lower()
    ):

        findings.append({
            "type": "Redirect",
            "severity": "MEDIUM",
            "finding": (
                f"Application redirected from "
                f"{original_host} to {final_host}."
            )
        })

    return findings


# ============================================================
# RISK SCORE
# ============================================================

def calculate_score(findings):

    weights = {
        "LOW": 5,
        "MEDIUM": 10,
        "HIGH": 20,
        "CRITICAL": 30
    }

    score = 0

    for finding in findings:

        severity = finding.get(
            "severity",
            "LOW"
        )

        score += weights.get(
            severity,
            5
        )

    return min(score, 100)


# ============================================================
# VERDICT
# ============================================================

def verdict_from_score(score):

    if score >= 65:
        return "HIGH RISK", "HIGH"

    if score >= 35:
        return "SUSPICIOUS", "MEDIUM"

    return "LOW RISK", "LOW"


# ============================================================
# MAIN SCANNER
# ============================================================

def scan_web_application(url):

    target = normalize_target(url)

    parsed = urlparse(target)

    hostname = parsed.hostname

    findings = []

    # --------------------------------------------------------
    # Transport
    # --------------------------------------------------------

    findings.extend(
        analyze_transport(target)
    )

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    dns = analyze_dns(hostname)

    # --------------------------------------------------------
    # HTTP request
    # --------------------------------------------------------

    try:

        response = requests.get(
            target,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={
                "User-Agent": USER_AGENT
            }
        )

    except requests.exceptions.SSLError as error:

        return {
            "success": False,
            "target": target,
            "error": "TLS/SSL validation failed.",
            "details": str(error)
        }

    except requests.exceptions.RequestException as error:

        return {
            "success": False,
            "target": target,
            "error": "Unable to connect to target.",
            "details": str(error)
        }

    # --------------------------------------------------------
    # Security headers
    # --------------------------------------------------------

    findings.extend(
        analyze_security_headers(
            response
        )
    )

    # --------------------------------------------------------
    # Cookies
    # --------------------------------------------------------

    findings.extend(
        analyze_cookies(
            response
        )
    )

    # --------------------------------------------------------
    # Server information
    # --------------------------------------------------------

    findings.extend(
        analyze_server_information(
            response
        )
    )

    # --------------------------------------------------------
    # CORS
    # --------------------------------------------------------

    findings.extend(
        analyze_cors(
            response
        )
    )

    # --------------------------------------------------------
    # Redirects
    # --------------------------------------------------------

    findings.extend(
        analyze_redirects(
            response,
            target
        )
    )

    # --------------------------------------------------------
    # Score
    # --------------------------------------------------------

    risk_score = calculate_score(
        findings
    )

    verdict, risk_level = verdict_from_score(
        risk_score
    )

    return {

        "success": True,

        "target": target,

        "http": {
            "status_code":
                response.status_code,

            "final_url":
                response.url,

            "response_time":
                None,

            "content_type":
                response.headers.get(
                    "content-type"
                )
        },

        "domain": {
            "hostname": hostname,

            "dns_resolved":
                dns["resolved"],

            "ip_addresses":
                dns["ip_addresses"]
        },

        "security": {

            "https":
                parsed.scheme == "https",

            "headers_checked":
                len(SECURITY_HEADERS),

            "findings":
                findings
        },

        "detection": {

            "verdict":
                verdict,

            "risk_level":
                risk_level,

            "risk_score":
                risk_score,

            "finding_count":
                len(findings)
        },

        "recommendations": [

            "Enable HTTPS for all application endpoints.",

            "Configure security headers such as HSTS and CSP.",

            "Protect cookies using Secure, HttpOnly and SameSite attributes.",

            "Avoid exposing unnecessary server and technology information.",

            "Review wildcard CORS configuration.",

            "Review redirects and ensure users remain on trusted domains."

        ]
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    result = scan_web_application(
        "https://example.com"
    )

    print("\nCyberSentinel Web Application Scan")
    print("----------------------------------")

    print(
        "Verdict:",
        result.get("detection", {}).get(
            "verdict"
        )
    )

    print(
        "Risk:",
        result.get("detection", {}).get(
            "risk_score"
        )
    )

    print(
        "Findings:",
        result.get("detection", {}).get(
            "finding_count"
        )
    )