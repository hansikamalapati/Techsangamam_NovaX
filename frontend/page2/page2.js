/* ============================================================
   CYBERSENTINEL - PAGE 2
   URL + MESSAGE + IMAGE + EMAIL + WEB APPLICATION SCANNER
   DETAILED SECURITY REPORT
   ============================================================ */


/* ============================================================
   CYBERSENTINEL - PAGE 2
   URL + MESSAGE + IMAGE + EMAIL + WEB APPLICATION SCANNER
   DETAILED SECURITY REPORT
   ============================================================ */

const API_BASE_URL = "";

let selectedScanType = "url";
let scanResult = null;


/* ============================================================
   PAGE LOAD
   ============================================================ */

document.addEventListener("DOMContentLoaded", function () {

    console.log("CyberSentinel Scanner loaded.");

    initializeScanner();
    setupReportButton();
    setupScanAgainButton();
    loadExistingResult();

});



/* ============================================================
   INITIALIZE SCANNER
   ============================================================ */

function initializeScanner() {

    const urlCard =
        document.getElementById("urlScanCard");

    const messageCard =
        document.getElementById("messageScanCard");

    const imageCard =
        document.getElementById("imageScanCard");

    const emailCard =
        document.getElementById("emailScanCard");

    const webAppCard =
        document.getElementById("webAppScanCard");

    const analyzeBtn =
        document.getElementById("analyzeBtn");

    const imageInput =
        document.getElementById("imageInput");


    /* --------------------------------------------------------
       URL CARD
       -------------------------------------------------------- */

    if (urlCard) {

        urlCard.addEventListener(
            "click",
            function () {

                selectScanType("url");

            }
        );

    }


    /* --------------------------------------------------------
       MESSAGE CARD
       -------------------------------------------------------- */

    if (messageCard) {

        messageCard.addEventListener(
            "click",
            function () {

                selectScanType("message");

            }
        );

    }


    /* --------------------------------------------------------
       IMAGE CARD
       -------------------------------------------------------- */

    if (imageCard) {

        imageCard.addEventListener(
            "click",
            function () {

                selectScanType("image");

            }
        );

    }


    /* --------------------------------------------------------
       EMAIL CARD
       -------------------------------------------------------- */

    if (emailCard) {

        emailCard.addEventListener(
            "click",
            function () {

                selectScanType("email");

            }
        );

    }


    /* --------------------------------------------------------
       WEB APPLICATION CARD
       -------------------------------------------------------- */

    if (webAppCard) {

        webAppCard.addEventListener(
            "click",
            function () {

                selectScanType("webapp");

            }
        );

    }


    /* --------------------------------------------------------
       ANALYZE BUTTON
       -------------------------------------------------------- */

    if (analyzeBtn) {

        analyzeBtn.addEventListener(
            "click",
            analyzeThreat
        );

    }


    /* --------------------------------------------------------
       IMAGE PREVIEW
       -------------------------------------------------------- */

    if (imageInput) {

        imageInput.addEventListener(
            "change",
            previewImage
        );

    }


    selectScanType("url");

}


/* ============================================================
   SELECT SCAN TYPE
   ============================================================ */

function selectScanType(type) {

    selectedScanType = type;


    const cards = [

        document.getElementById("urlScanCard"),

        document.getElementById("messageScanCard"),

        document.getElementById("imageScanCard"),

        document.getElementById("emailScanCard"),

        document.getElementById("webAppScanCard")

    ];


    cards.forEach(function (card) {

        if (card) {

            card.classList.remove("active");

        }

    });


    const sections = [

        document.getElementById("urlInputSection"),

        document.getElementById("messageInputSection"),

        document.getElementById("imageInputSection"),

        document.getElementById("emailInputSection"),

        document.getElementById("webAppInputSection")

    ];


    sections.forEach(function (section) {

        if (section) {

            section.classList.add("hidden");

        }

    });


    /* --------------------------------------------------------
       URL
       -------------------------------------------------------- */

    if (type === "url") {

        const card =
            document.getElementById("urlScanCard");

        const section =
            document.getElementById("urlInputSection");

        if (card) {

            card.classList.add("active");

        }

        if (section) {

            section.classList.remove("hidden");

        }

    }


    /* --------------------------------------------------------
       MESSAGE
       -------------------------------------------------------- */

    if (type === "message") {

        const card =
            document.getElementById("messageScanCard");

        const section =
            document.getElementById("messageInputSection");

        if (card) {

            card.classList.add("active");

        }

        if (section) {

            section.classList.remove("hidden");

        }

    }


    /* --------------------------------------------------------
       IMAGE
       -------------------------------------------------------- */

    if (type === "image") {

        const card =
            document.getElementById("imageScanCard");

        const section =
            document.getElementById("imageInputSection");

        if (card) {

            card.classList.add("active");

        }

        if (section) {

            section.classList.remove("hidden");

        }

    }


    /* --------------------------------------------------------
       EMAIL
       -------------------------------------------------------- */

    if (type === "email") {

        const card =
            document.getElementById("emailScanCard");

        const section =
            document.getElementById("emailInputSection");

        if (card) {

            card.classList.add("active");

        }

        if (section) {

            section.classList.remove("hidden");

        }

    }


    /* --------------------------------------------------------
       WEB APPLICATION
       -------------------------------------------------------- */

    if (type === "webapp") {

        const card =
            document.getElementById("webAppScanCard");

        const section =
            document.getElementById("webAppInputSection");

        if (card) {

            card.classList.add("active");

        }

        if (section) {

            section.classList.remove("hidden");

        }

    }

}


/* ============================================================
   ANALYZE THREAT
   ============================================================ */

async function analyzeThreat() {

    clearError();
    hideResults();
    setLoading(true);


    try {

        let data;


        /* ====================================================
           URL
           ==================================================== */

        if (selectedScanType === "url") {

            const input =
                document.getElementById("urlInput");

            const url =
                input
                    ? input.value.trim()
                    : "";


            if (!url) {

                throw new Error(
                    "Please enter a URL."
                );

            }


            if (!isValidURL(url)) {

                throw new Error(
                    "Please enter a valid URL."
                );

            }


            data =
                await scanURL(url);

        }


        /* ====================================================
           MESSAGE
           ==================================================== */

        else if (selectedScanType === "message") {

            const input =
                document.getElementById("messageInput");

            const message =
                input
                    ? input.value.trim()
                    : "";


            if (!message) {

                throw new Error(
                    "Please enter a message."
                );

            }


            data =
                await scanMessage(message);

        }


        /* ====================================================
           IMAGE
           ==================================================== */

        else if (selectedScanType === "image") {

            const input =
                document.getElementById("imageInput");


            if (
                !input ||
                !input.files ||
                input.files.length === 0
            ) {

                throw new Error(
                    "Please select an image."
                );

            }


            data =
                await scanImage(
                    input.files[0]
                );

        }


        /* ====================================================
           EMAIL
           ==================================================== */

        else if (selectedScanType === "email") {

            const senderInput =
                document.getElementById("emailSender");

            const subjectInput =
                document.getElementById("emailSubject");

            const bodyInput =
                document.getElementById("emailBody");


            const sender =
                senderInput
                    ? senderInput.value.trim()
                    : "";

            const subject =
                subjectInput
                    ? subjectInput.value.trim()
                    : "";

            const body =
                bodyInput
                    ? bodyInput.value.trim()
                    : "";


            if (
                !sender &&
                !subject &&
                !body
            ) {

                throw new Error(
                    "Please enter email content to analyze."
                );

            }


            data =
                await scanEmail(
                    sender,
                    subject,
                    body
                );

        }


        /* ====================================================
           WEB APPLICATION
           ==================================================== */

        else if (selectedScanType === "webapp") {

            const input =
                document.getElementById("webAppUrl");

            const url =
                input
                    ? input.value.trim()
                    : "";


            if (!url) {

                throw new Error(
                    "Please enter a web application URL."
                );

            }


            if (!isValidURL(url)) {

                throw new Error(
                    "Please enter a valid HTTP/HTTPS URL."
                );

            }


            data =
                await scanWebApp(url);

        }


        /* ====================================================
           CHECK RESULT
           ==================================================== */

        if (!data) {

            throw new Error(
                "No result was returned by the backend."
            );

        }


        scanResult = data;


        sessionStorage.setItem(
            "cyberSentinelResult",
            JSON.stringify(data)
        );


        displayResults(data);


        const results =
            document.getElementById("results");


        if (results) {

            results.scrollIntoView({
                behavior: "smooth"
            });

        }

    }


    catch (error) {

        console.error(
            "Scan error:",
            error
        );


        showError(
            error.message ||
            "Unable to analyze the input."
        );

    }


    finally {

        setLoading(false);

    }

}


/* ============================================================
   URL SCAN
   ============================================================ */

async function scanURL(url) {

    const response =
        await fetch(
            `${API_BASE_URL}/api/scan/url`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    url: url
                })
            }
        );


    return await readResponse(
        response
    );

}


/* ============================================================
   MESSAGE SCAN
   ============================================================ */

async function scanMessage(message) {

    const response =
        await fetch(
            `${API_BASE_URL}/api/scan/message`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    message: message
                })
            }
        );


    return await readResponse(
        response
    );

}


/* ============================================================
   EMAIL SCAN
   ============================================================ */

async function scanEmail(
    sender,
    subject,
    body
) {

    const response =
        await fetch(
            `${API_BASE_URL}/api/scan/email`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    sender: sender,
                    subject: subject,
                    body: body
                })
            }
        );


    return await readResponse(
        response
    );

}


/* ============================================================
   WEB APPLICATION SCAN
   ============================================================ */

async function scanWebApp(url) {

    const response =
        await fetch(
            `${API_BASE_URL}/api/scan/webapp`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    url: url
                })
            }
        );


    return await readResponse(
        response
    );

}


/* ============================================================
   IMAGE SCAN
   ============================================================ */

async function scanImage(file) {

    const formData =
        new FormData();


    formData.append(
        "file",
        file
    );


    const response =
        await fetch(
            `${API_BASE_URL}/api/scan/image`,
            {
                method: "POST",

                body: formData
            }
        );


    return await readResponse(
        response
    );

}


/* ============================================================
   READ RESPONSE
   ============================================================ */

async function readResponse(response) {

    let data;


    try {

        data =
            await response.json();

    }


    catch {

        throw new Error(
            "Backend returned an invalid response."
        );

    }


    if (!response.ok) {

        throw new Error(
            data.detail ||
            data.message ||
            "Backend request failed."
        );

    }


    return data;

}


/* ============================================================
   DISPLAY RESULTS
   ============================================================ */

function displayResults(data) {

    const result =
        data.result ||
        data.data ||
        data;


    const detection =
        result.detection ||
        {};


    const ai =
        result.ai_analysis ||
        {};


    const security =
        result.security_analysis ||
        {};


    const analysis =
        result.analysis ||
        {};


    const detailed =
        result.detailed_report ||
        {};


    /*
       Normalize top-level backend responses.

       This is useful because Email and Web App
       analyzers may return their main values at
       the top level instead of inside detection.
    */

    if (
        !detection.verdict &&
        result.verdict
    ) {

        detection.verdict =
            result.verdict;

    }


    if (
        detection.risk_score === undefined &&
        result.risk_score !== undefined
    ) {

        detection.risk_score =
            result.risk_score;

    }


    if (
        !detection.risk_level &&
        result.risk_level
    ) {

        detection.risk_level =
            result.risk_level;

    }


    if (
        !detection.threat_type &&
        result.threat_type
    ) {

        detection.threat_type =
            result.threat_type;

    }


    if (
        ai.phishing_probability === undefined &&
        result.phishing_probability !== undefined
    ) {

        ai.phishing_probability =
            result.phishing_probability;

    }


    if (
        ai.legitimate_probability === undefined &&
        result.legitimate_probability !== undefined
    ) {

        ai.legitimate_probability =
            result.legitimate_probability;

    }


    setText(
        "verdict",
        detection.verdict ||
        "UNKNOWN"
    );


    setText(
        "riskScore",
        formatNumber(
            detection.risk_score
        )
    );


    setText(
        "riskLevel",
        detection.risk_level ||
        "-"
    );


    setText(
        "threatType",
        detection.threat_type ||
        "-"
    );


    setText(
        "attackCategory",
        detection.attack_category ||
        detailed.attack_category ||
        "-"
    );


    setText(
        "aiPrediction",
        convertPrediction(
            ai.prediction
        )
    );


    setText(
        "phishingProbability",
        formatProbability(
            ai.phishing_probability
        )
    );


    setText(
        "legitimateProbability",
        formatProbability(
            ai.legitimate_probability
        )
    );


    setText(
        "ruleScore",
        security.rule_score ??
        "-"
    );


    renderDetailedAnalysis(
        result
    );


    const results =
        document.getElementById(
            "results"
        );


    if (results) {

        results.classList.remove(
            "hidden"
        );

    }

}
/* ============================================================
   DETAILED ANALYSIS
   ============================================================ */

function renderDetailedAnalysis(result) {

    const detailed =
        result.detailed_report ||
        {};

    const analysis =
        result.analysis ||
        {};

    const security =
        result.security_analysis ||
        {};

    const detection =
        result.detection ||
        {};


    /* --------------------------------------------------------
       SUMMARY
       -------------------------------------------------------- */

    setText(
        "analysisSummary",
        analysis.summary ||
        detailed.what_is_the_threat ||
        "Analysis completed."
    );


    /* --------------------------------------------------------
       ATTACK CATEGORY
       -------------------------------------------------------- */

    setText(
        "attackCategory",
        detection.attack_category ||
        detailed.attack_category ||
        "-"
    );


    /* --------------------------------------------------------
       ATTACK OBJECTIVE
       -------------------------------------------------------- */

    setText(
        "attackObjective",
        detection.attack_objective ||
        detailed.attack_objective ||
        "-"
    );


    /* --------------------------------------------------------
       WHAT IS THE THREAT
       -------------------------------------------------------- */

    setText(
        "whatIsTheThreat",
        detailed.what_is_the_threat ||
        "No threat description available."
    );


    /* --------------------------------------------------------
       HOW THE ATTACK WORKS
       -------------------------------------------------------- */

    setText(
        "howAttackWorks",
        detailed.how_the_attack_works ||
        "No attack explanation available."
    );


    /* --------------------------------------------------------
       RISK ANALYSIS
       -------------------------------------------------------- */

    setText(
        "riskAnalysis",
        detailed.risk_analysis ||
        "Risk analysis is not available."
    );


    /* --------------------------------------------------------
       AI EXPLANATION
       -------------------------------------------------------- */

    setText(
        "aiExplanation",
        detailed.ai_explanation ||
        "AI explanation is not available."
    );


    /* --------------------------------------------------------
       SECURITY RULE EXPLANATION
       -------------------------------------------------------- */

    setText(
        "securityRuleExplanation",
        detailed.security_rule_explanation ||
        "No security rule explanation available."
    );


    /* --------------------------------------------------------
       ATTACK SCENARIO
       -------------------------------------------------------- */

    renderList(
        "attackScenario",
        analysis.attack_scenario ||
        detailed.attack_chain ||
        []
    );


    /* --------------------------------------------------------
       POTENTIAL IMPACT
       -------------------------------------------------------- */

    renderList(
        "potentialImpact",
        analysis.potential_impact ||
        detailed.potential_impact ||
        []
    );


    /* --------------------------------------------------------
       REASONS
       -------------------------------------------------------- */

    renderList(
        "reasons",
        analysis.reasons ||
        []
    );


    /* --------------------------------------------------------
       EVIDENCE
       -------------------------------------------------------- */

    renderList(
        "evidence",
        detailed.evidence ||
        security.indicators ||
        []
    );


    /* --------------------------------------------------------
       PREVENTION
       -------------------------------------------------------- */

    renderList(
        "preventionSolution",
        detailed.prevention_solution ||
        result.recommendation ||
        []
    );


    /* --------------------------------------------------------
       ANALYST CONCLUSION
       -------------------------------------------------------- */

    setText(
        "analystConclusion",
        detailed.analyst_conclusion ||
        analysis.summary ||
        "Analysis completed."
    );


    /* --------------------------------------------------------
       RECOMMENDATION
       -------------------------------------------------------- */

    const recommendation =
        document.getElementById(
            "recommendation"
        );


    if (recommendation) {

        const recommendations =
            result.recommendation ||
            detailed.prevention_solution ||
            [];


        if (Array.isArray(recommendations)) {

            recommendation.innerHTML =
                recommendations
                    .map(
                        item =>
                            `<div class="recommendation-item">
                                • ${escapeHTML(item)}
                             </div>`
                    )
                    .join("");

        }

        else {

            recommendation.textContent =
                recommendations ||
                "No recommendation available.";

        }

    }


    /* --------------------------------------------------------
       SECURITY INDICATORS
       -------------------------------------------------------- */

    renderIndicators(
        security.indicators ||
        result.indicators ||
        []
    );


    /* --------------------------------------------------------
       URL ANALYSIS
       -------------------------------------------------------- */

    renderURLAnalysis(
        result.url_analysis ||
        result.urlAnalysis ||
        []
    );


    /* --------------------------------------------------------
       THREAT INTELLIGENCE
       -------------------------------------------------------- */

    renderThreatIntelligence(
        result.threat_intelligence ||
        result.threatIntelligence ||
        {}
    );


    /* --------------------------------------------------------
       OCR
       -------------------------------------------------------- */

    renderOCR(
        result.ocr ||
        result.ocr_analysis ||
        {}
    );


    /* --------------------------------------------------------
       WEB APPLICATION RESULTS
       -------------------------------------------------------- */

    renderWebApplicationResults(
        result
    );

}


/* ============================================================
   RENDER LIST
   ============================================================ */

function renderList(
    elementId,
    items
) {

    const element =
        document.getElementById(
            elementId
        );


    if (!element) {

        return;

    }


    element.innerHTML = "";


    if (
        !items ||
        items.length === 0
    ) {

        element.innerHTML =
            `<p class="empty-state">
                No information available.
             </p>`;

        return;

    }


    if (!Array.isArray(items)) {

        items = [
            items
        ];

    }


    items.forEach(
        function (item) {

            const div =
                document.createElement(
                    "div"
                );


            div.className =
                "analysis-item";


            if (
                typeof item === "object"
            ) {

                const text =
                    item.message ||
                    item.description ||
                    item.finding ||
                    item.reason ||
                    JSON.stringify(item);


                div.textContent =
                    `• ${text}`;

            }

            else {

                div.textContent =
                    `• ${item}`;

            }


            element.appendChild(
                div
            );

        }
    );

}


/* ============================================================
   SECURITY INDICATORS
   ============================================================ */

function renderIndicators(
    indicators
) {

    const container =
        document.getElementById(
            "indicators"
        );


    if (!container) {

        return;

    }


    container.innerHTML = "";


    if (
        !indicators ||
        indicators.length === 0
    ) {

        container.innerHTML =
            `<div class="indicator safe">
                ✓ No significant security indicators detected.
             </div>`;

        return;

    }


    if (!Array.isArray(indicators)) {

        indicators = [
            indicators
        ];

    }


    indicators.forEach(
        function (indicator) {

            const element =
                document.createElement(
                    "div"
                );


            element.className =
                "indicator";


            let text = "";
            let severity = "INFO";


            if (
                typeof indicator === "object"
            ) {

                const name =
                    indicator.indicator ||
                    indicator.type ||
                    indicator.name ||
                    "Security Indicator";


                severity =
                    (
                        indicator.severity ||
                        "INFO"
                    ).toUpperCase();


                const details =
                    indicator.details ||
                    indicator.finding ||
                    indicator.message ||
                    indicator.description ||
                    "";


                text =
                    details
                        ? `${name}: ${details}`
                        : name;

            }

            else {

                text =
                    String(indicator);

            }


            element.classList.add(
                getSeverityClass(
                    severity
                )
            );


            element.innerHTML = `

                <div class="indicator-header">

                    <strong>
                        ${escapeHTML(text)}
                    </strong>

                    <span class="severity-badge">
                        ${escapeHTML(severity)}
                    </span>

                </div>

            `;


            container.appendChild(
                element
            );

        }
    );

}


/* ============================================================
   SEVERITY CLASS
   ============================================================ */

function getSeverityClass(
    severity
) {

    switch (
        String(
            severity
        ).toUpperCase()
    ) {

        case "CRITICAL":
            return "critical";

        case "HIGH":
            return "high";

        case "MEDIUM":
            return "medium";

        case "LOW":
            return "low";

        case "SAFE":
            return "safe";

        default:
            return "info";

    }

}


/* ============================================================
   URL ANALYSIS
   ============================================================ */

function renderURLAnalysis(
    urlAnalysis
) {

    const container =
        document.getElementById(
            "urlAnalysis"
        );


    if (!container) {

        return;

    }


    container.innerHTML = "";


    if (
        !urlAnalysis ||
        urlAnalysis.length === 0
    ) {

        container.innerHTML =
            `<p class="empty-state">
                No URLs were extracted or analyzed.
             </p>`;

        return;

    }


    if (!Array.isArray(urlAnalysis)) {

        urlAnalysis = [
            urlAnalysis
        ];

    }


    urlAnalysis.forEach(
        function (item) {

            const card =
                document.createElement(
                    "div"
                );


            card.className =
                "url-result-card";


            let url = "";
            let status = "";
            let risk = "";
            let details = "";


            if (
                typeof item === "object"
            ) {

                url =
                    item.url ||
                    item.input ||
                    "";


                status =
                    item.status ||
                    item.verdict ||
                    item.prediction ||
                    "";


                risk =
                    item.risk_level ||
                    item.risk ||
                    "";


                details =
                    item.reason ||
                    item.details ||
                    "";

            }

            else {

                url =
                    String(item);

            }


            card.innerHTML = `

                <div class="url-result-url">

                    🔗

                    <span>
                        ${escapeHTML(url)}
                    </span>

                </div>


                <div class="url-result-details">

                    <span>
                        Status:
                        <strong>
                            ${escapeHTML(status || "-")}
                        </strong>
                    </span>


                    <span>
                        Risk:
                        <strong>
                            ${escapeHTML(risk || "-")}
                        </strong>
                    </span>

                </div>


                ${
                    details
                        ? `
                            <p>
                                ${escapeHTML(details)}
                            </p>
                          `
                        : ""
                }

            `;


            container.appendChild(
                card
            );

        }
    );

}


/* ============================================================
   THREAT INTELLIGENCE
   ============================================================ */

function renderThreatIntelligence(
    intelligence
) {

    const container =
        document.getElementById(
            "threatIntelligence"
        );


    if (!container) {

        return;

    }


    container.innerHTML = "";


    if (
        !intelligence ||
        Object.keys(intelligence).length === 0
    ) {

        container.textContent =
            "No threat intelligence information available.";

        return;

    }


    const matched =
        intelligence.matched;


    const status =
        intelligence.status ||
        "UNKNOWN";


    const source =
        intelligence.source ||
        "Threat Intelligence";


    const reason =
        intelligence.reason ||
        "";


    const domain =
        intelligence.domain ||
        "";


    const statusClass =
        matched
            ? "threat-found"
            : "threat-clear";


    container.innerHTML = `

        <div
            class="threat-intel-status ${statusClass}"
        >

            <strong>
                ${escapeHTML(status)}
            </strong>

        </div>


        <div class="threat-intel-details">

            <div>
                Source:
                <strong>
                    ${escapeHTML(source)}
                </strong>
            </div>


            ${
                domain
                    ? `
                        <div>
                            Domain:
                            <strong>
                                ${escapeHTML(domain)}
                            </strong>
                        </div>
                      `
                    : ""
            }


            ${
                reason
                    ? `
                        <div>
                            ${escapeHTML(reason)}
                        </div>
                      `
                    : ""
            }

        </div>

    `;

}


/* ============================================================
   OCR RESULTS
   ============================================================ */

function renderOCR(
    ocr
) {

    const section =
        document.getElementById(
            "ocrSection"
        );


    const textElement =
        document.getElementById(
            "ocrText"
        );


    if (!section || !textElement) {

        return;

    }


    const text =
        ocr.text ||
        ocr.extracted_text ||
        "";


    if (!text) {

        section.classList.add(
            "hidden"
        );

        textElement.textContent =
            "";

        return;

    }


    section.classList.remove(
        "hidden"
    );


    textElement.textContent =
        text;

}


/* ============================================================
   WEB APPLICATION RESULTS
   ============================================================ */

function renderWebApplicationResults(
    result
) {

    const section =
        document.getElementById(
            "webAppResultsSection"
        );


    if (!section) {

        return;

    }


    /*
       Only show this section for Web App scans.
    */

    if (
        selectedScanType !== "webapp"
    ) {

        section.classList.add(
            "hidden"
        );

        return;

    }


    section.classList.remove(
        "hidden"
    );


    const web =
        result.web_application_analysis ||
        result.webApplicationAnalysis ||
        result;


    const security =
        result.security_analysis ||
        web.security ||
        {};


    const httpStatus =
        web.http_status ||
        web.status_code ||
        security.http_status ||
        "-";


    const finalURL =
        web.final_url ||
        web.finalUrl ||
        result.url ||
        "-";


    const dns =
        web.dns_resolves ??
        web.dns_status ??
        security.dns_resolves;


    const https =
        web.https ??
        security.https;


    setText(
        "webHttpStatus",
        httpStatus
    );


    setText(
        "webFinalUrl",
        finalURL
    );


    setText(
        "webDnsStatus",
        formatBoolean(
            dns
        )
    );


    setText(
        "webHttpsStatus",
        formatBoolean(
            https
        )
    );


    const findings =
        web.findings ||
        security.indicators ||
        [];


    renderIndicators(
        findings
    );


    /*
       The generic indicator container is also used by
       URL/message scans. If a dedicated Web App findings
       container exists, render there as well.
    */

    const dedicated =
        document.getElementById(
            "webSecurityFindings"
        );


    if (dedicated) {

        dedicated.innerHTML = "";


        if (
            !findings ||
            findings.length === 0
        ) {

            dedicated.innerHTML =
                `<div class="indicator safe">
                    ✓ No significant security findings detected.
                 </div>`;

        }

        else {

            findings.forEach(
                function (finding) {

                    const item =
                        document.createElement(
                            "div"
                        );


                    item.className =
                        "indicator";


                    let text =
                        "";

                    let severity =
                        "INFO";


                    if (
                        typeof finding === "object"
                    ) {

                        text =
                            finding.finding ||
                            finding.message ||
                            finding.description ||
                            finding.type ||
                            "Security finding";


                        severity =
                            (
                                finding.severity ||
                                "INFO"
                            ).toUpperCase();

                    }

                    else {

                        text =
                            String(finding);

                    }


                    item.classList.add(
                        getSeverityClass(
                            severity
                        )
                    );


                    item.innerHTML = `

                        <div
                            class="indicator-header"
                        >

                            <strong>
                                ${escapeHTML(text)}
                            </strong>

                            <span
                                class="severity-badge"
                            >
                                ${escapeHTML(severity)}
                            </span>

                        </div>

                    `;


                    dedicated.appendChild(
                        item
                    );

                }
            );

        }

    }

}


/* ============================================================
   FORMAT BOOLEAN
   ============================================================ */

function formatBoolean(
    value
) {

    if (
        value === true ||
        value === 1 ||
        value === "true"
    ) {

        return "YES";

    }


    if (
        value === false ||
        value === 0 ||
        value === "false"
    ) {

        return "NO";

    }


    return "-";

}


/* ============================================================
   FORMAT NUMBER
   ============================================================ */

function formatNumber(
    value
) {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "-";

    }


    const number =
        Number(value);


    if (
        Number.isNaN(number)
    ) {

        return String(value);

    }


    return number.toFixed(2);

}


/* ============================================================
   FORMAT PROBABILITY
   ============================================================ */

function formatProbability(
    value
) {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "-";

    }


    let number =
        Number(value);


    if (
        Number.isNaN(number)
    ) {

        return String(value);

    }


    /*
       Backend normally returns a decimal between 0 and 1.
       If it returns a value greater than 1, assume it is
       already a percentage.
    */

    if (
        number <= 1
    ) {

        number =
            number * 100;

    }


    return (
        number.toFixed(2) +
        "%"
    );

}


/* ============================================================
   CONVERT AI PREDICTION
   ============================================================ */

function convertPrediction(
    prediction
) {

    if (
        prediction === undefined ||
        prediction === null
    ) {

        return "-";

    }


    const value =
        String(
            prediction
        ).toUpperCase();


    if (
        value === "0"
    ) {

        return "LEGITIMATE";

    }


    if (
        value === "1"
    ) {

        return "PHISHING";

    }


    return value;

}


/* ============================================================
   SET TEXT
   ============================================================ */

function setText(
    elementId,
    value
) {

    const element =
        document.getElementById(
            elementId
        );


    if (!element) {

        return;

    }


    if (
        value === undefined ||
        value === null
    ) {

        element.textContent =
            "-";

        return;

    }


    element.textContent =
        String(value);

}


/* ============================================================
   ESCAPE HTML
   ============================================================ */

function escapeHTML(
    value
) {

    if (
        value === undefined ||
        value === null
    ) {

        return "";

    }


    return String(value)
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );

}


/* ============================================================
   URL VALIDATION
   ============================================================ */

function isValidURL(
    value
) {

    try {

        const url =
            new URL(value);


        return (
            url.protocol ===
                "http:" ||
            url.protocol ===
                "https:"
        );

    }

    catch {

        return false;

    }

}


/* ============================================================
   IMAGE PREVIEW
   ============================================================ */

function previewImage(
    event
) {

    const file =
        event.target.files &&
        event.target.files[0];


    const preview =
        document.getElementById(
            "imagePreview"
        );


    if (!preview) {

        return;

    }


    preview.innerHTML =
        "";


    if (!file) {

        preview.classList.add(
            "hidden"
        );

        return;

    }


    if (
        !file.type.startsWith(
            "image/"
        )
    ) {

        preview.classList.add(
            "hidden"
        );

        showError(
            "Please select a valid image file."
        );

        return;

    }


    const reader =
        new FileReader();


    reader.onload =
        function (event) {

            const image =
                document.createElement(
                    "img"
                );


            image.src =
                event.target.result;


            image.alt =
                "Uploaded screenshot";


            image.className =
                "preview-image";


            preview.appendChild(
                image
            );


            preview.classList.remove(
                "hidden"
            );

        };


    reader.readAsDataURL(
        file
    );

}


/* ============================================================
   LOADING STATE
   ============================================================ */

function setLoading(
    loading
) {

    const element =
        document.getElementById(
            "loading"
        );


    const button =
        document.getElementById(
            "analyzeBtn"
        );


    if (element) {

        if (loading) {

            element.classList.remove(
                "hidden"
            );

        }

        else {

            element.classList.add(
                "hidden"
            );

        }

    }


    if (button) {

        button.disabled =
            loading;


        button.innerHTML =
            loading
                ? "⏳ Analyzing..."
                : "🔍 Analyze Threat";

    }

}


/* ============================================================
   ERROR HANDLING
   ============================================================ */

function showError(
    message
) {

    const error =
        document.getElementById(
            "scannerError"
        );


    if (!error) {

        alert(message);

        return;

    }


    error.textContent =
        message;


    error.classList.remove(
        "hidden"
    );

}


function clearError() {

    const error =
        document.getElementById(
            "scannerError"
        );


    if (error) {

        error.textContent =
            "";

        error.classList.add(
            "hidden"
        );

    }

}


/* ============================================================
   HIDE RESULTS
   ============================================================ */

function hideResults() {

    const results =
        document.getElementById(
            "results"
        );


    if (results) {

        results.classList.add(
            "hidden"
        );

    }


    const webResults =
        document.getElementById(
            "webAppResultsSection"
        );


    if (webResults) {

        webResults.classList.add(
            "hidden"
        );

    }

}


/* ============================================================
   LOAD PREVIOUS RESULT
   ============================================================ */

function loadExistingResult() {

    try {

        const saved =
            sessionStorage.getItem(
                "cyberSentinelResult"
            );


        if (!saved) {

            return;

        }


        const data =
            JSON.parse(
                saved
            );


        if (data) {

            scanResult =
                data;

        }

    }

    catch (error) {

        console.warn(
            "Could not load previous result:",
            error
        );

    }

}


/* ============================================================
   SCAN AGAIN
   ============================================================ */

function setupScanAgainButton() {

    const button =
        document.getElementById(
            "scanAgainBtn"
        );


    if (!button) {

        return;

    }


    button.addEventListener(
        "click",
        function () {

            const results =
                document.getElementById(
                    "results"
                );


            if (results) {

                results.classList.add(
                    "hidden"
                );

            }


            window.scrollTo({
                top: 0,
                behavior: "smooth"
            });

        }
    );

}


/* ============================================================
   REPORT BUTTON
   ============================================================ */

function setupReportButton() {

    const button =
        document.getElementById(
            "downloadReportBtn"
        );


    if (!button) {

        return;

    }


    button.addEventListener(
        "click",
        downloadSecurityReport
    );

}


/* ============================================================
   DOWNLOAD SECURITY REPORT
   ============================================================ */

function downloadSecurityReport() {

    if (!scanResult) {

        showError(
            "Please perform a scan before downloading the report."
        );

        return;

    }


    const result =
        scanResult.result ||
        scanResult.data ||
        scanResult;


    const detection =
        result.detection ||
        {};


    const ai =
        result.ai_analysis ||
        {};


    const detailed =
        result.detailed_report ||
        {};


    const analysis =
        result.analysis ||
        {};


    const reportLines = [];


    reportLines.push(
        "============================================================"
    );

    reportLines.push(
        "                 CYBERSENTINEL SECURITY REPORT"
    );

    reportLines.push(
        "============================================================"
    );


    reportLines.push(
        ""
    );


    reportLines.push(
        "FINAL VERDICT"
    );


    reportLines.push(
        "------------------------------------------------------------"
    );


    reportLines.push(
        `Verdict       : ${
            detection.verdict || "-"
        }`
    );


    reportLines.push(
        `Risk Score    : ${
            detection.risk_score ?? "-"
        }/100`
    );


    reportLines.push(
        `Risk Level    : ${
            detection.risk_level || "-"
        }`
    );


    reportLines.push(
        `Threat Type   : ${
            detection.threat_type || "-"
        }`
    );


    reportLines.push(
        `Category      : ${
            detection.attack_category ||
            detailed.attack_category ||
            "-"
        }`
    );


    reportLines.push(
        ""
    );


    reportLines.push(
        "AI ANALYSIS"
    );


    reportLines.push(
        "------------------------------------------------------------"
    );


    reportLines.push(
        `Prediction             : ${
            convertPrediction(
                ai.prediction
            )
        }`
    );


    reportLines.push(
        `Phishing Probability   : ${
            formatProbability(
                ai.phishing_probability
            )
        }`
    );


    reportLines.push(
        `Legitimate Probability : ${
            formatProbability(
                ai.legitimate_probability
            )
        }`
    );


    reportLines.push(
        `Model                  : ${
            ai.model || "-"
        }`
    );


    reportLines.push(
        `Architecture           : ${
            ai.architecture || "-"
        }`
    );


    reportLines.push(
        ""
    );


    reportLines.push(
        "THREAT ANALYSIS"
    );


    reportLines.push(
        "------------------------------------------------------------"
    );


    reportLines.push(
        `Summary:\n${
            analysis.summary ||
            detailed.what_is_the_threat ||
            "-"
        }`
    );


    reportLines.push(
        ""
    );


    reportLines.push(
        `Attack Objective:\n${
            detection.attack_objective ||
            detailed.attack_objective ||
            "-"
        }`
    );


    reportLines.push(
        ""
    );


    reportLines.push(
        `How the Attack Works:\n${
            detailed.how_the_attack_works ||
            "-"
        }`
    );


    reportLines.push(
        ""
    );


    reportLines.push(
        "SECURITY INDICATORS"
    );


    reportLines.push(
        "------------------------------------------------------------"
    );


    const indicators =
        result.security_analysis &&
        result.security_analysis.indicators;


    if (
        Array.isArray(indicators) &&
        indicators.length
    ) {

        indicators.forEach(
            function (item) {

                if (
                    typeof item === "object"
                ) {

                    reportLines.push(
                        `• ${
                            item.indicator ||
                            item.type ||
                            item.finding ||
                            item.message ||
                            JSON.stringify(item)
                        }`
                    );

                }

                else {

                    reportLines.push(
                        `• ${item}`
                    );

                }

            }
        );

    }

    else {

        reportLines.push(
            "No significant indicators detected."
        );

    }


    reportLines.push(
        ""
    );


    reportLines.push(
        "POTENTIAL IMPACT"
    );


    reportLines.push(
        "------------------------------------------------------------"
    );


    const impact =
        analysis.potential_impact ||
        detailed.potential_impact ||
        [];


    if (
        Array.isArray(impact)
    ) {

        impact.forEach(
            item =>
                reportLines.push(
                    `• ${item}`
                )
        );

    }

    else {

        reportLines.push(
            String(
                impact || "-"
            )
        );

    }


    reportLines.push(
        ""
    );


    reportLines.push(
        "PREVENTION"
    );


    reportLines.push(
        "------------------------------------------------------------"
    );


    const prevention =
        detailed.prevention_solution ||
        result.recommendation ||
        [];


    if (
        Array.isArray(prevention)
    ) {

        prevention.forEach(
            item =>
                reportLines.push(
                    `• ${item}`
                )
        );

    }

    else {

        reportLines.push(
            String(
                prevention || "-"
            )
        );

    }


    reportLines.push(
        ""
    );


    reportLines.push(
        "============================================================"
    );


    reportLines.push(
        "Generated by CyberSentinel"
    );


    reportLines.push(
        "============================================================"
    );


    const blob =
        new Blob(
            [
                reportLines.join(
                    "\n"
                )
            ],
            {
                type:
                    "text/plain;charset=utf-8"
            }
        );


    const url =
        URL.createObjectURL(
            blob
        );


    const link =
        document.createElement(
            "a"
        );


    link.href =
        url;


    link.download =
        "CyberSentinel_Security_Report.txt";


    document.body.appendChild(
        link
    );


    link.click();


    document.body.removeChild(
        link
    );


    URL.revokeObjectURL(
        url
    );

}
/* ============================================================
   UI HELPERS
   ============================================================ */

function showResults() {

    const results =
        document.getElementById("results");

    if (results) {

        results.classList.remove("hidden");

    }

}


function hideResults() {

    const results =
        document.getElementById("results");

    if (results) {

        results.classList.add("hidden");

    }


    const webAppResults =
        document.getElementById(
            "webAppResultsSection"
        );

    if (webAppResults) {

        webAppResults.classList.add("hidden");

    }

}


/* ============================================================
   SCAN STATUS
   ============================================================ */

function updateScanStatus(
    message
) {

    const status =
        document.getElementById(
            "scanStatus"
        );

    if (!status) {

        return;

    }


    status.textContent =
        message || "";

}


/* ============================================================
   LOADING OVERLAY
   ============================================================ */

function showLoading(
    message = "Analyzing..."
) {

    const loading =
        document.getElementById(
            "loading"
        );


    if (loading) {

        loading.classList.remove(
            "hidden"
        );


        const text =
            loading.querySelector(
                ".loading-text"
            );


        if (text) {

            text.textContent =
                message;

        }

    }


    const button =
        document.getElementById(
            "analyzeBtn"
        );


    if (button) {

        button.disabled =
            true;


        button.dataset.originalText =
            button.innerHTML;


        button.innerHTML =
            "⏳ Analyzing...";

    }

}


function hideLoading() {

    const loading =
        document.getElementById(
            "loading"
        );


    if (loading) {

        loading.classList.add(
            "hidden"
        );

    }


    const button =
        document.getElementById(
            "analyzeBtn"
        );


    if (button) {

        button.disabled =
            false;


        button.innerHTML =
            button.dataset.originalText ||
            "🔍 Analyze Threat";

    }

}


/* ============================================================
   ERROR DISPLAY
   ============================================================ */

function showError(
    message
) {

    console.error(
        "CyberSentinel:",
        message
    );


    const error =
        document.getElementById(
            "scannerError"
        );


    if (error) {

        error.textContent =
            message;


        error.classList.remove(
            "hidden"
        );


        error.scrollIntoView({
            behavior: "smooth",
            block: "center"
        });


        return;

    }


    /*
       Fallback if the HTML does not contain
       the dedicated error element.
    */

    alert(
        message
    );

}


function clearError() {

    const error =
        document.getElementById(
            "scannerError"
        );


    if (error) {

        error.textContent =
            "";


        error.classList.add(
            "hidden"
        );

    }

}


/* ============================================================
   GENERIC TEXT SETTER
   ============================================================ */

function setText(
    id,
    value
) {

    const element =
        document.getElementById(
            id
        );


    if (!element) {

        return;

    }


    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        element.textContent =
            "-";

        return;

    }


    element.textContent =
        String(value);

}


/* ============================================================
   GENERIC HTML SETTER
   ============================================================ */

function setHTML(
    id,
    html
) {

    const element =
        document.getElementById(
            id
        );


    if (!element) {

        return;

    }


    element.innerHTML =
        html || "";

}


/* ============================================================
   SAFE HTML ESCAPING
   ============================================================ */

function escapeHTML(
    value
) {

    if (
        value === undefined ||
        value === null
    ) {

        return "";

    }


    return String(value)
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );

}


/* ============================================================
   NUMBER FORMATTING
   ============================================================ */

function formatNumber(
    value,
    decimals = 2
) {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "-";

    }


    const number =
        Number(value);


    if (
        Number.isNaN(number)
    ) {

        return String(value);

    }


    return number.toFixed(
        decimals
    );

}


/* ============================================================
   RISK SCORE FORMATTING
   ============================================================ */

function formatRiskScore(
    value
) {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "-";

    }


    const score =
        Number(value);


    if (
        Number.isNaN(score)
    ) {

        return String(value);

    }


    return Math.round(
        Math.max(
            0,
            Math.min(
                100,
                score
            )
        )
    );

}


/* ============================================================
   PROBABILITY FORMATTING
   ============================================================ */

function formatProbability(
    value
) {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "-";

    }


    let probability =
        Number(value);


    if (
        Number.isNaN(
            probability
        )
    ) {

        return String(value);

    }


    /*
       Backend may return either:
       0.95  -> 95%
       95    -> 95%
    */

    if (
        probability >= 0 &&
        probability <= 1
    ) {

        probability *=
            100;

    }


    probability =
        Math.max(
            0,
            Math.min(
                100,
                probability
            )
        );


    return (
        probability.toFixed(2) +
        "%"
    );

}


/* ============================================================
   PREDICTION NORMALIZATION
   ============================================================ */

function normalizePrediction(
    prediction
) {

    if (
        prediction === undefined ||
        prediction === null
    ) {

        return "-";

    }


    const value =
        String(
            prediction
        )
        .trim()
        .toUpperCase();


    if (
        value === "0" ||
        value === "LEGITIMATE" ||
        value === "SAFE" ||
        value === "BENIGN"
    ) {

        return "LEGITIMATE";

    }


    if (
        value === "1" ||
        value === "PHISHING" ||
        value === "MALICIOUS" ||
        value === "DANGEROUS"
    ) {

        return "PHISHING";

    }


    return value;

}


/* ============================================================
   RISK LEVEL NORMALIZATION
   ============================================================ */

function normalizeRiskLevel(
    level
) {

    if (
        level === undefined ||
        level === null
    ) {

        return "UNKNOWN";

    }


    return String(
        level
    )
        .trim()
        .toUpperCase();

}


/* ============================================================
   VERDICT CLASS
   ============================================================ */

function getVerdictClass(
    verdict
) {

    const value =
        String(
            verdict || ""
        )
        .toUpperCase();


    if (
        value.includes(
            "PHISH"
        ) ||
        value.includes(
            "MALICIOUS"
        ) ||
        value.includes(
            "DANGEROUS"
        )
    ) {

        return "danger";

    }


    if (
        value.includes(
            "SUSPICIOUS"
        )
    ) {

        return "warning";

    }


    if (
        value.includes(
            "LEGITIMATE"
        ) ||
        value.includes(
            "SAFE"
        ) ||
        value.includes(
            "BENIGN"
        )
    ) {

        return "safe";

    }


    return "unknown";

}


/* ============================================================
   RISK LEVEL CLASS
   ============================================================ */

function getRiskClass(
    level
) {

    const value =
        normalizeRiskLevel(
            level
        );


    switch (value) {

        case "CRITICAL":
            return "critical";

        case "HIGH":
            return "high";

        case "MEDIUM":
            return "medium";

        case "LOW":
            return "low";

        case "SAFE":
            return "safe";

        default:
            return "unknown";

    }

}


/* ============================================================
   DISPLAY RISK SCORE
   ============================================================ */

function displayRiskScore(
    score
) {

    const formatted =
        formatRiskScore(
            score
        );


    setText(
        "riskScore",
        formatted
    );


    const progress =
        document.getElementById(
            "riskProgress"
        );


    if (progress) {

        const numeric =
            Number(score);


        if (
            !Number.isNaN(
                numeric
            )
        ) {

            progress.style.width =
                `${Math.max(
                    0,
                    Math.min(
                        100,
                        numeric
                    )
                )}%`;

        }

    }

}


/* ============================================================
   DISPLAY VERDICT
   ============================================================ */

function displayVerdict(
    verdict
) {

    const normalized =
        normalizePrediction(
            verdict
        );


    setText(
        "verdict",
        normalized
    );


    const element =
        document.getElementById(
            "verdict"
        );


    if (element) {

        element.classList.remove(
            "safe",
            "danger",
            "warning",
            "unknown"
        );


        element.classList.add(
            getVerdictClass(
                normalized
            )
        );

    }

}


/* ============================================================
   DISPLAY RISK LEVEL
   ============================================================ */

function displayRiskLevel(
    level
) {

    const normalized =
        normalizeRiskLevel(
            level
        );


    setText(
        "riskLevel",
        normalized
    );


    const element =
        document.getElementById(
            "riskLevel"
        );


    if (element) {

        element.classList.remove(
            "critical",
            "high",
            "medium",
            "low",
            "safe",
            "unknown"
        );


        element.classList.add(
            getRiskClass(
                normalized
            )
        );

    }

}


/* ============================================================
   RENDER ARRAY AS BULLETS
   ============================================================ */

function renderBulletList(
    elementId,
    items
) {

    const element =
        document.getElementById(
            elementId
        );


    if (!element) {

        return;

    }


    element.innerHTML =
        "";


    if (
        !items ||
        (
            Array.isArray(items) &&
            items.length === 0
        )
    ) {

        element.innerHTML =
            `<div class="empty-state">
                No information available.
             </div>`;

        return;

    }


    if (
        !Array.isArray(items)
    ) {

        items =
            [
                items
            ];

    }


    items.forEach(
        function (item) {

            const row =
                document.createElement(
                    "div"
                );


            row.className =
                "analysis-item";


            let text =
                "";


            if (
                typeof item ===
                "object"
            ) {

                text =
                    item.message ||
                    item.description ||
                    item.reason ||
                    item.finding ||
                    item.name ||
                    JSON.stringify(
                        item
                    );

            }

            else {

                text =
                    String(item);

            }


            row.innerHTML =
                `• ${escapeHTML(
                    text
                )}`;


            element.appendChild(
                row
            );

        }
    );

}


/* ============================================================
   RENDER KEY/VALUE INFORMATION
   ============================================================ */

function renderKeyValue(
    elementId,
    object
) {

    const container =
        document.getElementById(
            elementId
        );


    if (!container) {

        return;

    }


    container.innerHTML =
        "";


    if (
        !object ||
        typeof object !==
        "object"
    ) {

        container.innerHTML =
            `<div class="empty-state">
                No information available.
             </div>`;

        return;

    }


    Object.entries(
        object
    ).forEach(
        function (
            [
                key,
                value
            ]
        ) {

            if (
                value === undefined ||
                value === null
            ) {

                return;

            }


            const row =
                document.createElement(
                    "div"
                );


            row.className =
                "key-value-row";


            let displayValue;


            if (
                typeof value ===
                "object"
            ) {

                displayValue =
                    JSON.stringify(
                        value
                    );

            }

            else {

                displayValue =
                    String(value);

            }


            row.innerHTML = `

                <span class="key">
                    ${escapeHTML(
                        formatKey(
                            key
                        )
                    )}
                </span>

                <span class="value">
                    ${escapeHTML(
                        displayValue
                    )}
                </span>

            `;


            container.appendChild(
                row
            );

        }
    );

}


/* ============================================================
   FORMAT KEY
   ============================================================ */

function formatKey(
    key
) {

    return String(
        key || ""
    )
        .replace(
            /_/g,
            " "
        )
        .replace(
            /([a-z])([A-Z])/g,
            "$1 $2"
        )
        .replace(
            /\b\w/g,
            function (letter) {
                return letter.toUpperCase();
            }
        );

}


/* ============================================================
   GENERIC ARRAY NORMALIZER
   ============================================================ */

function toArray(
    value
) {

    if (
        value === undefined ||
        value === null
    ) {

        return [];

    }


    if (
        Array.isArray(value)
    ) {

        return value;

    }


    return [
        value
    ];

}


/* ============================================================
   BOOLEAN FORMATTER
   ============================================================ */

function formatBoolean(
    value
) {

    if (
        value === true ||
        value === 1 ||
        value === "true"
    ) {

        return "YES";

    }


    if (
        value === false ||
        value === 0 ||
        value === "false"
    ) {

        return "NO";

    }


    return "-";

}
/* ============================================================
   RENDER SECURITY INDICATORS
   ============================================================ */

function renderIndicators(indicators) {

    const containers = [

        document.getElementById(
            "indicators"
        ),

        document.getElementById(
            "securityIndicators"
        ),

        document.getElementById(
            "webSecurityFindings"
        )

    ];


    const uniqueContainers =
        containers.filter(
            function (element, index) {

                return (
                    element &&
                    containers.indexOf(
                        element
                    ) === index
                );

            }
        );


    if (
        uniqueContainers.length === 0
    ) {

        return;

    }


    indicators =
        toArray(
            indicators
        );


    uniqueContainers.forEach(
        function (container) {

            container.innerHTML =
                "";


            if (
                indicators.length === 0
            ) {

                container.innerHTML = `
                    <div class="indicator safe">
                        ✓ No significant security indicators detected.
                    </div>
                `;

                return;

            }


            indicators.forEach(
                function (indicator) {

                    const element =
                        document.createElement(
                            "div"
                        );


                    element.className =
                        "indicator";


                    let message =
                        "";

                    let severity =
                        "INFO";


                    if (
                        typeof indicator ===
                        "object"
                    ) {

                        message =
                            indicator.message ||
                            indicator.description ||
                            indicator.finding ||
                            indicator.indicator ||
                            indicator.reason ||
                            indicator.type ||
                            "Security indicator";


                        severity =
                            String(
                                indicator.severity ||
                                "INFO"
                            ).toUpperCase();

                    }

                    else {

                        message =
                            String(
                                indicator
                            );

                    }


                    element.classList.add(
                        getSeverityClass(
                            severity
                        )
                    );


                    element.innerHTML = `

                        <div class="indicator-header">

                            <span>
                                ${escapeHTML(
                                    message
                                )}
                            </span>

                            <span class="severity-badge">

                                ${escapeHTML(
                                    severity
                                )}

                            </span>

                        </div>

                    `;


                    container.appendChild(
                        element
                    );

                }
            );

        }
    );

}


/* ============================================================
   RENDER THREAT INTELLIGENCE
   ============================================================ */

function renderThreatIntelligence(
    intelligence
) {

    const container =
        document.getElementById(
            "threatIntelligence"
        );


    if (!container) {

        return;

    }


    container.innerHTML =
        "";


    if (
        !intelligence ||
        typeof intelligence !==
        "object"
    ) {

        container.innerHTML = `
            <div class="empty-state">
                No threat intelligence data available.
            </div>
        `;

        return;

    }


    const matched =
        Boolean(
            intelligence.matched
        );


    const status =
        intelligence.status ||
        (
            matched
                ? "KNOWN_THREAT"
                : "NOT_FOUND"
        );


    const source =
        intelligence.source ||
        "Threat Intelligence";


    const reason =
        intelligence.reason ||
        "No additional information available.";


    const domain =
        intelligence.domain ||
        "";


    container.innerHTML = `

        <div class="
            threat-intelligence-card
            ${matched
                ? "threat-found"
                : "threat-clear"}
        ">

            <div class="threat-status">

                ${
                    matched
                        ? "⚠️ Known Threat"
                        : "✓ No Known Threat Match"
                }

            </div>


            <div class="threat-status-name">

                ${escapeHTML(
                    status
                )}

            </div>


            <div class="threat-source">

                Source:
                <strong>
                    ${escapeHTML(
                        source
                    )}
                </strong>

            </div>


            ${
                domain
                    ? `
                        <div class="threat-domain">

                            Domain:
                            <strong>
                                ${escapeHTML(
                                    domain
                                )}
                            </strong>

                        </div>
                      `
                    : ""
            }


            <div class="threat-reason">

                ${escapeHTML(
                    reason
                )}

            </div>

        </div>

    `;

}


/* ============================================================
   RENDER OCR
   ============================================================ */

function renderOCR(
    ocr
) {

    const section =
        document.getElementById(
            "ocrSection"
        );


    const textElement =
        document.getElementById(
            "ocrText"
        );


    if (
        !section ||
        !textElement
    ) {

        return;

    }


    const text =
        (
            ocr &&
            (
                ocr.text ||
                ocr.extracted_text ||
                ocr.ocr_text
            )
        ) || "";


    if (!text.trim()) {

        section.classList.add(
            "hidden"
        );


        textElement.textContent =
            "";


        return;

    }


    section.classList.remove(
        "hidden"
    );


    textElement.textContent =
        text;

}


/* ============================================================
   RENDER WEB APPLICATION RESULTS
   ============================================================ */

function renderWebApplicationResults(
    result
) {

    const section =
        document.getElementById(
            "webAppResultsSection"
        );


    if (!section) {

        return;

    }


    if (
        selectedScanType !==
        "webapp"
    ) {

        section.classList.add(
            "hidden"
        );

        return;

    }


    section.classList.remove(
        "hidden"
    );


    const web =
        result.web_application_analysis ||
        result.webApplicationAnalysis ||
        result.web_app_analysis ||
        {};


    const security =
        result.security_analysis ||
        web.security_analysis ||
        web.security ||
        {};


    const url =
        web.url ||
        result.url ||
        "-";


    const finalURL =
        web.final_url ||
        web.finalUrl ||
        "-";


    const statusCode =
        web.status_code ||
        web.http_status ||
        web.httpStatus ||
        "-";


    const server =
        web.server ||
        web.server_header ||
        "-";


    const contentType =
        web.content_type ||
        web.contentType ||
        "-";


    const dns =
        web.dns_resolves ??
        web.dns_status ??
        null;


    const https =
        web.https ??
        web.https_enabled ??
        null;


    setText(
        "webAppTarget",
        url
    );


    setText(
        "webHttpStatus",
        statusCode
    );


    setText(
        "webFinalUrl",
        finalURL
    );


    setText(
        "webServer",
        server
    );


    setText(
        "webContentType",
        contentType
    );


    setText(
        "webDnsStatus",
        formatBoolean(
            dns
        )
    );


    setText(
        "webHttpsStatus",
        formatBoolean(
            https
        )
    );


    const findings =
        web.findings ||
        web.security_findings ||
        security.indicators ||
        [];


    const dedicated =
        document.getElementById(
            "webSecurityFindings"
        );


    if (
        dedicated
    ) {

        dedicated.innerHTML =
            "";


        const list =
            toArray(
                findings
            );


        if (
            list.length === 0
        ) {

            dedicated.innerHTML = `
                <div class="indicator safe">

                    ✓ No significant web
                    application findings detected.

                </div>
            `;

        }

        else {

            list.forEach(
                function (finding) {

                    const element =
                        document.createElement(
                            "div"
                        );


                    let text =
                        "";

                    let severity =
                        "INFO";


                    if (
                        typeof finding ===
                        "object"
                    ) {

                        text =
                            finding.message ||
                            finding.description ||
                            finding.finding ||
                            finding.reason ||
                            finding.type ||
                            "Security finding";


                        severity =
                            String(
                                finding.severity ||
                                "INFO"
                            ).toUpperCase();

                    }

                    else {

                        text =
                            String(
                                finding
                            );

                    }


                    element.className =
                        `indicator ${
                            getSeverityClass(
                                severity
                            )
                        }`;


                    element.innerHTML = `

                        <div class="indicator-header">

                            <strong>
                                ${escapeHTML(
                                    text
                                )}
                            </strong>

                            <span class="severity-badge">

                                ${escapeHTML(
                                    severity
                                )}

                            </span>

                        </div>

                    `;


                    dedicated.appendChild(
                        element
                    );

                }
            );

        }

    }

}


/* ============================================================
   RENDER DOMAIN ANALYSIS
   ============================================================ */

function renderDomainAnalysis(
    domainAnalysis
) {

    const container =
        document.getElementById(
            "domainAnalysis"
        );


    if (!container) {

        return;

    }


    container.innerHTML =
        "";


    if (
        !domainAnalysis ||
        typeof domainAnalysis !==
        "object"
    ) {

        return;

    }


    const rows = [

        [
            "Hostname",
            domainAnalysis.hostname
        ],

        [
            "Registered Domain",
            domainAnalysis.registered_domain
        ],

        [
            "Domain",
            domainAnalysis.domain
        ],

        [
            "Subdomain",
            domainAnalysis.subdomain
        ],

        [
            "TLD",
            domainAnalysis.tld
        ],

        [
            "HTTPS",
            formatBoolean(
                domainAnalysis.https
            )
        ],

        [
            "IP Address",
            formatBoolean(
                domainAnalysis.is_ip
            )
        ],

        [
            "DNS Resolves",
            formatBoolean(
                domainAnalysis.dns_resolves
            )
        ]

    ];


    rows.forEach(
        function (
            [
                label,
                value
            ]
        ) {

            if (
                value === undefined ||
                value === null ||
                value === ""
            ) {

                return;

            }


            const row =
                document.createElement(
                    "div"
                );


            row.className =
                "key-value-row";


            row.innerHTML = `

                <span class="key">

                    ${escapeHTML(
                        label
                    )}

                </span>

                <span class="value">

                    ${escapeHTML(
                        value
                    )}

                </span>

            `;


            container.appendChild(
                row
            );

        }
    );

}


/* ============================================================
   RENDER TYPOSQUATTING
   ============================================================ */

function renderTyposquatting(
    typo
) {

    const container =
        document.getElementById(
            "typosquatting"
        );


    if (!container) {

        return;

    }


    container.innerHTML =
        "";


    if (
        !typo ||
        typeof typo !==
        "object"
    ) {

        container.innerHTML =
            `<div class="empty-state">
                No typosquatting information available.
             </div>`;

        return;

    }


    const detected =
        Boolean(
            typo.detected
        );


    const closestBrand =
        typo.closest_brand ||
        "-";


    const similarity =
        typo.similarity_percent !==
        undefined
            ? `${typo.similarity_percent}%`
            : "-";


    const distance =
        typo.edit_distance !==
        undefined
            ? typo.edit_distance
            : "-";


    const method =
        typo.method ||
        "-";


    const score =
        typo.typosquatting_score !==
        undefined
            ? typo.typosquatting_score
            : "-";


    container.innerHTML = `

        <div class="
            typosquatting-card
            ${detected
                ? "danger"
                : "safe"}
        ">

            <div>

                <strong>
                    ${
                        detected
                            ? "⚠️ Typosquatting Detected"
                            : "✓ No Typosquatting Detected"
                    }
                </strong>

            </div>


            <div class="key-value-row">

                <span class="key">
                    Closest Brand
                </span>

                <span class="value">
                    ${escapeHTML(
                        closestBrand
                    )}
                </span>

            </div>


            <div class="key-value-row">

                <span class="key">
                    Similarity
                </span>

                <span class="value">
                    ${escapeHTML(
                        similarity
                    )}
                </span>

            </div>


            <div class="key-value-row">

                <span class="key">
                    Edit Distance
                </span>

                <span class="value">
                    ${escapeHTML(
                        distance
                    )}
                </span>

            </div>


            <div class="key-value-row">

                <span class="key">
                    Detection Method
                </span>

                <span class="value">
                    ${escapeHTML(
                        method
                    )}
                </span>

            </div>


            <div class="key-value-row">

                <span class="key">
                    Typosquatting Score
                </span>

                <span class="value">
                    ${escapeHTML(
                        score
                    )}/100
                </span>

            </div>

        </div>

    `;

}


/* ============================================================
   RENDER FEATURES
   ============================================================ */

function renderFeatures(
    features
) {

    const container =
        document.getElementById(
            "featureList"
        );


    if (!container) {

        return;

    }


    container.innerHTML =
        "";


    if (
        !features ||
        typeof features !==
        "object"
    ) {

        container.innerHTML =
            `<div class="empty-state">
                No feature information available.
             </div>`;

        return;

    }


    Object.entries(
        features
    ).forEach(
        function (
            [
                key,
                value
            ]
        ) {

            const row =
                document.createElement(
                    "div"
                );


            row.className =
                "feature-row";


            let displayValue;


            if (
                typeof value ===
                "number"
            ) {

                displayValue =
                    Number.isInteger(
                        value
                    )
                        ? value
                        : value.toFixed(
                            4
                        );

            }

            else if (
                typeof value ===
                "boolean"
            ) {

                displayValue =
                    value
                        ? "YES"
                        : "NO";

            }

            else {

                displayValue =
                    String(
                        value
                    );

            }


            row.innerHTML = `

                <span class="feature-name">

                    ${escapeHTML(
                        formatKey(
                            key
                        )
                    )}

                </span>

                <span class="feature-value">

                    ${escapeHTML(
                        displayValue
                    )}

                </span>

            `;


            container.appendChild(
                row
            );

        }
    );

}


/* ============================================================
   SHOW/HIDE OPTIONAL SECTIONS
   ============================================================ */

function toggleSection(
    id,
    show
) {

    const element =
        document.getElementById(
            id
        );


    if (!element) {

        return;

    }


    if (show) {

        element.classList.remove(
            "hidden"
        );

    }

    else {

        element.classList.add(
            "hidden"
        );

    }

}


/* ============================================================
   RESET FORM
   ============================================================ */

function resetScanner() {

    const inputs =
        document.querySelectorAll(
            "input, textarea"
        );


    inputs.forEach(
        function (input) {

            /*
               Don't reset unrelated page controls.
            */

            if (
                input.closest(
                    ".scanner"
                ) ||
                input.closest(
                    "#scanner"
                )
            ) {

                if (
                    input.type ===
                    "file"
                ) {

                    input.value =
                        "";

                }

                else {

                    input.value =
                        "";

                }

            }

        }
    );


    clearError();
    hideResults();


    const preview =
        document.getElementById(
            "imagePreview"
        );


    if (preview) {

        preview.innerHTML =
            "";

        preview.classList.add(
            "hidden"
        );

    }


    scanResult =
        null;


    sessionStorage.removeItem(
        "cyberSentinelResult"
    );


    selectScanType(
        "url"
    );

}


/* ============================================================
   KEYBOARD SHORTCUT
   ============================================================ */

document.addEventListener(
    "keydown",
    function (event) {

        /*
           Ctrl + Enter starts a scan.
        */

        if (
            event.ctrlKey &&
            event.key ===
            "Enter"
        ) {

            event.preventDefault();


            const button =
                document.getElementById(
                    "analyzeBtn"
                );


            if (
                button &&
                !button.disabled
            ) {

                analyzeThreat();

            }

        }

    }
);


/* ============================================================
   EXPORT FUNCTIONS
   ============================================================ */

window.CyberSentinel = {

    scanURL,

    scanMessage,

    scanEmail,

    scanWebApp,

    scanImage,

    analyzeThreat,

    selectScanType,

    resetScanner,

    displayResults,

    renderDetailedAnalysis

};


/* ============================================================
   FINAL INITIALIZATION
   ============================================================ */

console.log(
    "CyberSentinel frontend initialized."
);

console.log(
    "Supported scanners:",
    [
        "URL",
        "Message",
        "Image",
        "Email",
        "Web Application"
    ]
);

/* ============================================================
   AI CHATBOT NAVIGATION
   ============================================================ */

document.addEventListener("DOMContentLoaded", function () {

    const aiChatbotBtn =
        document.getElementById("aiChatbotBtn");

    if (aiChatbotBtn) {

        aiChatbotBtn.addEventListener("click", function () {

            window.location.href =
                "../page3/page3.html";

        });

    }


    const aiAssistantLink =
        document.querySelector(".ai-nav-btn");

    if (aiAssistantLink) {

        aiAssistantLink.addEventListener("click", function (event) {

            event.preventDefault();

            window.location.href =
                "../page3/page3.html";

        });

    }

});