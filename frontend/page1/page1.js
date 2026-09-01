/* ============================================================
   CYBERSENTINEL - PAGE 1 JAVASCRIPT
   ============================================================ */


/* ============================================================
   START SCANNING
   ============================================================ */

/*
   Page 1 is the landing page.

   When the user clicks "Start Scanning",
   we move to Page 2 where the actual
   URL / Message / Screenshot scanning happens.
*/

function startScanning() {

    window.location.href = "../page2/page2.html";

}


/* ============================================================
   LEARN MORE
   ============================================================ */

/*
   Scrolls the user to the Features section.
*/

function showFeatures() {

    const featuresSection =
        document.getElementById("features");

    if (featuresSection) {

        featuresSection.scrollIntoView({
            behavior: "smooth"
        });

    }

}


/* ============================================================
   NAVIGATION
   ============================================================ */

document.addEventListener("DOMContentLoaded", function () {


    /*
       Smooth scrolling for navigation links
    */

    const navLinks =
        document.querySelectorAll(
            '.nav-links a[href^="#"]'
        );


    navLinks.forEach(function (link) {

        link.addEventListener(
            "click",
            function (event) {

                event.preventDefault();

                const targetId =
                    this.getAttribute("href");

                const target =
                    document.querySelector(targetId);


                if (target) {

                    target.scrollIntoView({
                        behavior: "smooth"
                    });

                }

            }
        );

    });


    /* ========================================================
       SIMPLE SCROLL EFFECT
       ======================================================== */

    const navbar =
        document.querySelector(".navbar");


    window.addEventListener(
        "scroll",
        function () {

            if (!navbar) {
                return;
            }


            if (window.scrollY > 50) {

                navbar.style.boxShadow =
                    "0 4px 20px rgba(20, 40, 70, 0.08)";

            } else {

                navbar.style.boxShadow =
                    "none";

            }

        }
    );


    /* ========================================================
       FEATURE CARD ANIMATION
       ======================================================== */

    const featureCards =
        document.querySelectorAll(
            ".feature-card"
        );


    featureCards.forEach(function (card) {

        card.addEventListener(
            "mouseenter",
            function () {

                this.style.transform =
                    "translateY(-6px)";

            }
        );


        card.addEventListener(
            "mouseleave",
            function () {

                this.style.transform =
                    "translateY(0)";

            }
        );

    });


    /* ========================================================
       PAGE LOADED MESSAGE
       ======================================================== */

    console.log(
        "CyberSentinel Page 1 loaded successfully."
    );

    console.log(
        "AI-powered cybersecurity platform ready."
    );

});