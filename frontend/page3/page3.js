/* ============================================================
   CYBERSENTINEL - PAGE 3
   REAL AI CYBERSECURITY ASSISTANT
   ============================================================ */


/* ============================================================
   CONFIGURATION
   ============================================================ */

const API_BASE_URL = "http://127.0.0.1:8000";

const CHAT_ENDPOINT =
    `${API_BASE_URL}/api/chat`;

const CHAT_STORAGE_KEY =
    "cyberSentinelChatHistory";

const SCAN_STORAGE_KEY =
    "cyberSentinelResult";


/* ============================================================
   APPLICATION STATE
   ============================================================ */

let chatHistory = [];

let scanContext = null;

let isSending = false;


/* ============================================================
   PAGE LOAD
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    function () {

        console.log(
            "CyberSentinel AI Assistant loaded."
        );

        loadScanContext();

        loadChatHistory();

        setupChatInput();

        setupSendButton();

        setupSuggestionButtons();

        setupClearChat();

        setupRemoveContext();

        scrollChatToBottom();

    }
);


/* ============================================================
   CHAT INPUT SETUP
   ============================================================ */

function setupChatInput() {

    const input =
        document.getElementById(
            "chatInput"
        );


    if (!input) {

        console.error(
            "chatInput element not found."
        );

        return;

    }


    /*
       Enter = send message

       Shift + Enter = new line
    */

    input.addEventListener(
        "keydown",
        function (event) {

            if (
                event.key === "Enter" &&
                !event.shiftKey
            ) {

                event.preventDefault();

                sendMessage();

            }

        }
    );


    /*
       Automatically resize textarea
    */

    input.addEventListener(
        "input",
        function () {

            autoResizeInput(
                input
            );

        }
    );

}


/* ============================================================
   AUTO RESIZE TEXTAREA
   ============================================================ */

function autoResizeInput(
    input
) {

    input.style.height =
        "auto";


    input.style.height =
        Math.min(
            input.scrollHeight,
            130
        ) + "px";

}


/* ============================================================
   SEND BUTTON
   ============================================================ */

function setupSendButton() {

    const button =
        document.getElementById(
            "sendMessageBtn"
        );


    if (!button) {

        console.error(
            "sendMessageBtn element not found."
        );

        return;

    }


    button.addEventListener(
        "click",
        sendMessage
    );

}


/* ============================================================
   SUGGESTED QUESTIONS
   ============================================================ */

function setupSuggestionButtons() {

    const buttons =
        document.querySelectorAll(
            ".suggestion-btn"
        );


    buttons.forEach(
        function (button) {

            button.addEventListener(
                "click",
                function () {

                    if (isSending) {

                        return;

                    }


                    const question =
                        button.dataset.question ||
                        button.textContent.trim();


                    const input =
                        document.getElementById(
                            "chatInput"
                        );


                    if (!input) {

                        return;

                    }


                    input.value =
                        question;


                    autoResizeInput(
                        input
                    );


                    input.focus();

                    sendMessage();

                }
            );

        }
    );

}


/* ============================================================
   SEND MESSAGE
   ============================================================ */

async function sendMessage() {

    if (isSending) {

        return;

    }


    const input =
        document.getElementById(
            "chatInput"
        );


    if (!input) {

        return;

    }


    const message =
        input.value.trim();


    if (!message) {

        return;

    }


    /*
       IMPORTANT:

       Copy the history BEFORE adding the
       current question.

       Otherwise the current question
       gets sent twice to Gemini.
    */

    const previousHistory =
        chatHistory.map(
            function (item) {

                return {
                    role:
                        item.role,

                    content:
                        item.content
                };

            }
        );


    /*
       Clear input
    */

    input.value = "";

    autoResizeInput(
        input
    );


    /*
       Display user's message
    */

    addMessage(
        "user",
        message
    );


    /*
       Lock chat while Gemini is responding
    */

    isSending =
        true;

    setChatLoading(
        true
    );


    showTyping();


    try {

        /*
           Send the question,
           previous conversation,
           and latest scan context
           to the backend.
        */

        const response =
            await fetch(
                CHAT_ENDPOINT,
                {

                    method:
                        "POST",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body:
                        JSON.stringify({

                            message:
                                message,

                            history:
                                previousHistory,

                            context:
                                scanContext,

                            scan_context:
                                scanContext

                        })

                }
            );


        const data =
            await parseChatResponse(
                response
            );


        hideTyping();


        /*
           Extract Gemini response
        */

        const answer =
            extractAssistantResponse(
                data
            );


        /*
           Display Gemini response
        */

        addMessage(
            "bot",
            answer
        );


        /*
           If backend returns its own
           updated history, use it.
        */

        if (
            Array.isArray(
                data.history
            )
        ) {

            chatHistory =
                data.history;

        }


        /*
           Otherwise addMessage()
           already updated history.
        */

        saveChatHistory();


    }

    catch (error) {

        console.error(
            "CyberSentinel AI error:",
            error
        );


        hideTyping();


        /*
           Show the actual error when
           possible, making debugging easier.
        */

        let errorMessage =
            "I couldn't connect to the CyberSentinel AI service.";


        if (
            error &&
            error.message
        ) {

            errorMessage +=
                `\n\nDetails: ${error.message}`;

        }


        addMessage(
            "bot",
            errorMessage
        );

    }

    finally {

        isSending =
            false;

        setChatLoading(
            false
        );

    }

}


/* ============================================================
   PARSE BACKEND RESPONSE
   ============================================================ */

async function parseChatResponse(
    response
) {

    let data;


    try {

        data =
            await response.json();

    }

    catch (error) {

        throw new Error(
            `Server returned HTTP ${response.status}, `
            + `but the response was not valid JSON.`
        );

    }


    if (!response.ok) {

        const detail =
            data.detail ||
            data.error ||
            data.message ||
            `HTTP ${response.status}`;


        throw new Error(
            detail
        );

    }


    return data;

}


/* ============================================================
   EXTRACT AI RESPONSE
   ============================================================ */

function extractAssistantResponse(
    data
) {

    if (!data) {

        throw new Error(
            "The AI server returned an empty response."
        );

    }


    /*
       Standard response from our
       Gemini backend:

       {
           success: true,
           message: "..."
       }
    */

    if (
        typeof data.message ===
        "string" &&
        data.message.trim()
    ) {

        return data.message.trim();

    }


    /*
       Alternative response format
    */

    if (
        typeof data.response ===
        "string" &&
        data.response.trim()
    ) {

        return data.response.trim();

    }


    /*
       Another possible format
    */

    if (
        typeof data.answer ===
        "string" &&
        data.answer.trim()
    ) {

        return data.answer.trim();

    }


    /*
       Nested response
    */

    if (
        data.data &&
        typeof data.data.message ===
        "string"
    ) {

        return data.data.message.trim();

    }


    if (
        data.data &&
        typeof data.data.response ===
        "string"
    ) {

        return data.data.response.trim();

    }


    throw new Error(
        "The AI server returned no readable answer."
    );

}


/* ============================================================
   ADD MESSAGE TO CHAT
   ============================================================ */

function addMessage(
    sender,
    message
) {

    const container =
        document.getElementById(
            "chatMessages"
        );


    if (!container) {

        return;

    }


    const isUser =
        sender === "user";


    /*
       Create message row
    */

    const row =
        document.createElement(
            "div"
        );


    row.className =
        isUser
            ? "message-row user-row"
            : "message-row bot-row";


    /*
       Avatar
    */

    const avatar =
        document.createElement(
            "div"
        );


    avatar.className =
        "message-avatar";


    avatar.textContent =
        isUser
            ? "👤"
            : "🤖";


    /*
       Message content
    */

    const content =
        document.createElement(
            "div"
        );


    content.className =
        "message-content";


    /*
       Name
    */

    const name =
        document.createElement(
            "div"
        );


    name.className =
        "message-name";


    name.textContent =
        isUser
            ? "You"
            : "CyberSentinel AI";


    /*
       Message bubble
    */

    const bubble =
        document.createElement(
            "div"
        );


    bubble.className =
        isUser
            ? "message-bubble user-bubble"
            : "message-bubble bot-bubble";


    /*
       Safely render AI text
    */

    bubble.innerHTML =
        formatChatMessage(
            message
        );


    /*
       Time
    */

    const time =
        document.createElement(
            "div"
        );


    time.className =
        "message-time";


    time.textContent =
        getCurrentTime();


    /*
       Assemble
    */

    content.appendChild(
        name
    );

    content.appendChild(
        bubble
    );

    content.appendChild(
        time
    );


    row.appendChild(
        avatar
    );

    row.appendChild(
        content
    );


    container.appendChild(
        row
    );


    /*
       Add to conversation history
    */

    chatHistory.push({

        role:
            isUser
                ? "user"
                : "assistant",

        content:
            String(message)

    });


    /*
       Save immediately
    */

    saveChatHistory();


    /*
       Scroll down
    */

    scrollChatToBottom();

}


/* ============================================================
   FORMAT AI MESSAGE
   ============================================================ */

function formatChatMessage(
    message
) {

    if (
        message === null ||
        message === undefined
    ) {

        return "";

    }


    let text =
        escapeHTML(
            String(message)
        );


    /*
       Bold markdown:

       **text**

       becomes:

       <strong>text</strong>
    */

    text =
        text.replace(
            /\*\*(.*?)\*\*/g,
            "<strong>$1</strong>"
        );


    /*
       Markdown headings
    */

    text =
        text.replace(
            /^###\s+(.*)$/gm,
            "<strong>$1</strong>"
        );


    text =
        text.replace(
            /^##\s+(.*)$/gm,
            "<strong>$1</strong>"
        );


    text =
        text.replace(
            /^#\s+(.*)$/gm,
            "<strong>$1</strong>"
        );


    /*
       Convert bullet points.

       We use a span rather than
       inserting <li> without a
       <ul>.
    */

    text =
        text.replace(
            /(^|\n)[•*-]\s+(.*)/g,
            '$1<span class="chat-list-item">• $2</span>'
        );


    /*
       Numbered lists
    */

    text =
        text.replace(
            /(^|\n)(\d+)\.\s+(.*)/g,
            '$1<span class="chat-list-item">$2. $3</span>'
        );


    /*
       New lines
    */

    text =
        text.replace(
            /\n/g,
            "<br>"
        );


    return text;

}


/* ============================================================
   ESCAPE HTML
   ============================================================ */

function escapeHTML(
    value
) {

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
   TYPING INDICATOR
   ============================================================ */

function showTyping() {

    const typing =
        document.getElementById(
            "typingIndicator"
        );


    if (!typing) {

        return;

    }


    typing.classList.remove(
        "hidden"
    );


    scrollChatToBottom();

}


/* ============================================================
   HIDE TYPING INDICATOR
   ============================================================ */

function hideTyping() {

    const typing =
        document.getElementById(
            "typingIndicator"
        );


    if (!typing) {

        return;

    }


    typing.classList.add(
        "hidden"
    );

}


/* ============================================================
   CHAT LOADING STATE
   ============================================================ */

function setChatLoading(
    loading
) {

    const button =
        document.getElementById(
            "sendMessageBtn"
        );


    const input =
        document.getElementById(
            "chatInput"
        );


    if (button) {

        button.disabled =
            loading;

    }


    /*
       Do NOT disable textarea.

       The user can still see and
       interact with it naturally.
    */

    if (input) {

        input.disabled =
            false;

    }


    /*
       Update button appearance
       through aria state.
    */

    if (button) {

        button.setAttribute(
            "aria-busy",
            loading
                ? "true"
                : "false"
        );

    }


    if (
        !loading &&
        input
    ) {

        input.focus();

    }

}


/* ============================================================
   SCROLL CHAT TO BOTTOM
   ============================================================ */

function scrollChatToBottom() {

    const container =
        document.getElementById(
            "chatMessages"
        );


    if (!container) {

        return;

    }


    setTimeout(
        function () {

            container.scrollTop =
                container.scrollHeight;

        },
        50
    );

}


/* ============================================================
   CURRENT TIME
   ============================================================ */

function getCurrentTime() {

    return new Date()
        .toLocaleTimeString(
            [],
            {
                hour:
                    "2-digit",

                minute:
                    "2-digit"
            }
        );

}


/* ============================================================
   CLEAR CHAT SETUP
   ============================================================ */

function setupClearChat() {

    const button =
        document.getElementById(
            "clearChatBtn"
        );


    if (!button) {

        return;

    }


    button.addEventListener(
        "click",
        clearChat
    );

}


/* ============================================================
   CLEAR CHAT
   ============================================================ */

function clearChat() {

    const container =
        document.getElementById(
            "chatMessages"
        );


    if (!container) {

        return;

    }


    /*
       Reset conversation history
    */

    chatHistory = [];


    localStorage.removeItem(
        CHAT_STORAGE_KEY
    );


    /*
       Restore initial assistant message
    */

    container.innerHTML = `

        <div class="message-row bot-row">

            <div class="message-avatar">
                🤖
            </div>

            <div class="message-content">

                <div class="message-name">
                    CyberSentinel AI
                </div>

                <div class="message-bubble bot-bubble">

                    <p>
                        Hello! 👋 I'm CyberSentinel AI,
                        your cybersecurity assistant.
                    </p>

                    <p>
                        Ask me anything about cybersecurity,
                        phishing, suspicious URLs, threat
                        reports, account security, or your
                        latest CyberSentinel scan.
                    </p>

                </div>

                <div class="message-time">
                    ${getCurrentTime()}
                </div>

            </div>

        </div>

    `;


    scrollChatToBottom();

}


/* ============================================================
   SAVE CHAT HISTORY
   ============================================================ */

function saveChatHistory() {

    try {

        localStorage.setItem(
            CHAT_STORAGE_KEY,
            JSON.stringify(
                chatHistory
            )
        );

    }

    catch (error) {

        console.warn(
            "Unable to save chat history:",
            error
        );

    }

}


/* ============================================================
   LOAD CHAT HISTORY
   ============================================================ */

function loadChatHistory() {

    const stored =
        localStorage.getItem(
            CHAT_STORAGE_KEY
        );


    if (!stored) {

        return;

    }


    try {

        const history =
            JSON.parse(
                stored
            );


        if (
            !Array.isArray(
                history
            )
        ) {

            return;

        }


        /*
           Limit history so localStorage
           and Gemini requests don't grow
           indefinitely.
        */

        chatHistory =
            history.slice(
                -30
            );


        /*
           Display saved messages.

           addMessageToUI() is deliberately
           used here so we don't push them
           into chatHistory a second time.
        */

        chatHistory.forEach(
            function (item) {

                if (
                    !item ||
                    !item.content
                ) {

                    return;

                }


                addMessageToUI(
                    item.role,
                    item.content
                );

            }
        );

    }

    catch (error) {

        console.warn(
            "Could not load chat history:",
            error
        );


        chatHistory = [];

    }

}


/* ============================================================
   ADD SAVED MESSAGE TO UI
   ============================================================ */

function addMessageToUI(
    role,
    message
) {

    const container =
        document.getElementById(
            "chatMessages"
        );


    if (!container) {

        return;

    }


    const isUser =
        role === "user";


    const row =
        document.createElement(
            "div"
        );


    row.className =
        isUser
            ? "message-row user-row"
            : "message-row bot-row";


    const avatar =
        document.createElement(
            "div"
        );


    avatar.className =
        "message-avatar";


    avatar.textContent =
        isUser
            ? "👤"
            : "🤖";


    const content =
        document.createElement(
            "div"
        );


    content.className =
        "message-content";


    const name =
        document.createElement(
            "div"
        );


    name.className =
        "message-name";


    name.textContent =
        isUser
            ? "You"
            : "CyberSentinel AI";


    const bubble =
        document.createElement(
            "div"
        );


    bubble.className =
        isUser
            ? "message-bubble user-bubble"
            : "message-bubble bot-bubble";


    bubble.innerHTML =
        formatChatMessage(
            message
        );


    const time =
        document.createElement(
            "div"
        );


    time.className =
        "message-time";


    time.textContent =
        "Earlier";


    content.appendChild(
        name
    );

    content.appendChild(
        bubble
    );

    content.appendChild(
        time
    );


    row.appendChild(
        avatar
    );

    row.appendChild(
        content
    );


    container.appendChild(
        row
    );

}


/* ============================================================
   LOAD LATEST CYBERSENTINEL SCAN
   ============================================================ */

function loadScanContext() {

    const stored =
        sessionStorage.getItem(
            SCAN_STORAGE_KEY
        );


    if (!stored) {

        console.log(
            "No latest CyberSentinel scan found."
        );

        return;

    }


    try {

        const scan =
            JSON.parse(
                stored
            );


        /*
           Support multiple storage formats.
        */

        const result =
            scan.result ||
            scan.data ||
            scan;


        if (!result) {

            return;

        }


        scanContext =
            createScanContext(
                result
            );


        displayScanContext(
            result
        );


        console.log(
            "Latest CyberSentinel scan loaded:",
            scanContext
        );

    }

    catch (error) {

        console.warn(
            "Could not load scan context:",
            error
        );


        scanContext =
            null;

    }

}


/* ============================================================
   CREATE COMPACT SCAN CONTEXT
   ============================================================ */

function createScanContext(
    result
) {

    const detection =
        result.detection ||
        {};


    const ai =
        result.ai_analysis ||
        {};


    const security =
        result.security_analysis ||
        {};


    const detailed =
        result.detailed_report ||
        {};


    return {

        input_type:
            result.input_type ||
            result.input_kind ||
            null,

        input:
            result.input ||
            result.url ||
            result.message ||
            null,

        verdict:
            detection.verdict ||
            result.verdict ||
            null,

        risk_score:
            detection.risk_score ??
            result.risk_score ??
            null,

        risk_level:
            detection.risk_level ||
            result.risk_level ||
            null,

        threat_type:
            detection.threat_type ||
            result.threat_type ||
            null,

        attack_category:
            detection.attack_category ||
            detailed.attack_category ||
            result.attack_category ||
            null,

        attack_objective:
            detection.attack_objective ||
            detailed.attack_objective ||
            result.attack_objective ||
            null,

        ai_prediction:
            ai.prediction ||
            result.ai_prediction ||
            null,

        phishing_probability:
            ai.phishing_probability ??
            result.phishing_probability ??
            null,

        legitimate_probability:
            ai.legitimate_probability ??
            result.legitimate_probability ??
            null,

        rule_score:
            security.rule_score ??
            result.rule_score ??
            null,

        indicators:
            security.indicators ||
            detailed.evidence ||
            result.indicators ||
            [],

        detected_keywords:
            security.detected_keywords ||
            result.detected_keywords ||
            {},

        reasons:
            result.reasons ||
            detailed.reasons ||
            [],

        attack_scenario:
            result.attack_scenario ||
            detailed.attack_scenario ||
            [],

        potential_impact:
            result.potential_impact ||
            detailed.potential_impact ||
            [],

        recommendation:
            result.recommendation ||
            result.recommendations ||
            detailed.recommendations ||
            [],

        security_guidance:
            result.security_guidance ||
            detailed.security_guidance ||
            [],

        threat_intelligence:
            result.threat_intelligence ||
            null,

        ocr_text:
            result.ocr_text ||
            result.extracted_text ||
            null

    };

}


/* ============================================================
   DISPLAY SCAN CONTEXT
   ============================================================ */

function displayScanContext(
    result
) {

    const contextBox =
        document.getElementById(
            "scanContext"
        );


    const contextText =
        document.getElementById(
            "contextText"
        );


    if (
        !contextBox ||
        !contextText
    ) {

        return;

    }


    const detection =
        result.detection ||
        {};


    const threat =
        detection.threat_type ||
        result.threat_type ||
        "security threat";


    const risk =
        detection.risk_level ||
        result.risk_level ||
        "UNKNOWN";


    const score =
        detection.risk_score ??
        result.risk_score;


    let text =
        `Latest scan: ${threat}. `
        + `Risk level: ${risk}.`;


    if (
        score !== undefined &&
        score !== null
    ) {

        const numericScore =
            Number(score);


        if (
            !Number.isNaN(
                numericScore
            )
        ) {

            text +=
                ` Risk score: `
                + `${numericScore.toFixed(2)}/100.`;

        }

    }


    text +=
        " Ask me to explain the scan.";


    contextText.textContent =
        text;


    contextBox.classList.remove(
        "hidden"
    );

}


/* ============================================================
   REMOVE SCAN CONTEXT
   ============================================================ */

function setupRemoveContext() {

    const button =
        document.getElementById(
            "removeContextBtn"
        );


    if (!button) {

        return;

    }


    button.addEventListener(
        "click",
        function () {

            scanContext =
                null;


            const contextBox =
                document.getElementById(
                    "scanContext"
                );


            if (contextBox) {

                contextBox.classList.add(
                    "hidden"
                );

            }

        }
    );

}


/* ============================================================
   GET CURRENT SCAN CONTEXT
   ============================================================ */

function getScanContext() {

    if (!scanContext) {

        return null;

    }


    return scanContext;

}


/* ============================================================
   OPTIONAL: REFRESH SCAN CONTEXT
   ============================================================ */

function refreshScanContext() {

    loadScanContext();

}


/* ============================================================
   EXPOSE PUBLIC FUNCTIONS
   ============================================================ */

window.CyberSentinelAI = {

    sendMessage:
        sendMessage,

    clearChat:
        clearChat,

    loadScanContext:
        loadScanContext,

    refreshScanContext:
        refreshScanContext,

    getScanContext:
        getScanContext

};


/* ============================================================
   END OF PAGE3.JS
   ============================================================ */