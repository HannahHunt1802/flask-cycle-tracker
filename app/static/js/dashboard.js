// dashboard.js

document.addEventListener("DOMContentLoaded", function () {

    const tabs = document.querySelectorAll(".tab");
    const contents = document.querySelectorAll(".tab-content");
    const log_period_btn = document.querySelector(".log-period-btn");
    const logoutForm = document.getElementById("logout-form");

    let calendarRendered = false; // render calendar only once

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
                log_period_btn.style.display = "block";
                return;
            }

            // Activate clicked tab
            tabs.forEach(t => t.classList.remove("active"));
            contents.forEach(c => c.classList.remove("active"));

            tab.classList.add("active");

            const targetElement = document.getElementById(target);
            if (targetElement) targetElement.classList.add("active");

            log_period_btn.style.display = "none";

            // initalize calendar
            if (target === "calendar-tab" && !calendarRendered) {

                if (typeof FullCalendar === "undefined") {
                    console.error("FullCalendar is not defined. Check script order.");
                    return;
                }

                const calendarEl = document.getElementById("calendar");

                if (!calendarEl) {
                    console.error("#calendar element not found.");
                    return;
                }

                const calendar = new FullCalendar.Calendar(calendarEl, {
                    initialView: "dayGridMonth",
                    height: "auto",
                    headerToolbar: {
                        left: "prev,next today",
                        center: "title",
                        right: "dayGridMonth,timeGridWeek,timeGridDay"
                    },
                    events: window.user_periods || []
                });

                calendar.render();
                calendarRendered = true;
            }
        });
    });

});
