document.addEventListener("DOMContentLoaded", function () {

    const tabs = document.querySelectorAll(".tab");
    const contents = document.querySelectorAll(".tab-content");
    const log_period_btn = document.querySelector(".log-period-btn");
    const logoutForm = document.getElementById("logout-form");

    let calendarRendered = false; // render calendar only once

    // make calendar variable available now
    (function initCalendar() {
        if (typeof FullCalendar === "undefined") {
            console.error("FullCalendar is not defined. Ensure it is loaded before dashboard.js");
            return;
        }

        const calendarEl = document.getElementById("calendar");
        if (!calendarEl) {
            console.warn("#calendar element not found in DOM. Calendar can only be initialized when DOM contains #calendar.");
            return;
        }

        // build instance
        calendar = new FullCalendar.Calendar(calendarEl, {
            initialView: "dayGridMonth",
            selectable: true,
            editable: true,
            eventDurationEditable: true,
            height: "auto",
            headerToolbar: {
                left: "prev,next today",
                center: "title",
                right: ""
            },
            events: window.user_periods || []
        });

        // render calendar
        calendar.render();
        calendarRendered = true;
        console.log("Calendar initialized and rendered.");
    })();

    tabs.forEach(tab => {
        tab.addEventListener("click", (e) => {
            e.preventDefault();
            const target = tab.getAttribute("data-target");

            // handle logout tab
            if (target === "logout-tab" && logoutForm) {
                logoutForm.submit();
                return;
            }

            // Deactivate active tab
            if (tab.classList.contains("active")) {
                tab.classList.remove("active");
                const targetElement = document.getElementById(target);
                if (targetElement) targetElement.classList.remove("active");
                if (log_period_btn) log_period_btn.style.display = "block";
                return;
            }

            // Activate clicked tab
            tabs.forEach(t => t.classList.remove("active"));
            contents.forEach(c => c.classList.remove("active"));

            tab.classList.add("active");

            const targetElement = document.getElementById(target);
            if (targetElement) targetElement.classList.add("active");

            if (log_period_btn) log_period_btn.style.display = "none";

            if (target === "calendar-tab" && calendarRendered && calendar) {
                setTimeout(() => {
                    try {
                        calendar.updateSize();
                    } catch (err) {
                        console.warn("calendar.updateSize failed", err);
                    }
                }, 50);
            }
        });
    });

    if (typeof FullCalendar === "undefined") {
        console.error("FullCalendar is undefined at DOMContentLoaded. Ensure this script loads AFTER FullCalendar, e.g. include FullCalendar <script> before dashboard.js in the template");
    }
});
