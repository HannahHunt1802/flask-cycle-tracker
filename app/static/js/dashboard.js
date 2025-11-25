const tabs = document.querySelectorAll(".tab");
const contents = document.querySelectorAll(".tab-content");
const log_period_btn = document.querySelector(".log-period-btn");
const logoutForm = document.getElementById("logout-form");

tabs.forEach(tab => {
    tab.addEventListener("click", (e) => {
        e.preventDefault();
        const target = tab.getAttribute("data-target");

        // handle logout tab
        if (target === "logout-tab" && logoutForm) {
            logoutForm.submit();
            return;
        }

        // if the tab is already active, deactivate it
        if (tab.classList.contains("active")) {
            tab.classList.remove("active");
            const targetElement = document.getElementById(target);
            if (targetElement) targetElement.classList.remove("active");
            log_period_btn.style.display = "block";
        }
        // if the tab is not active, activate it
        else {
            tabs.forEach(t => t.classList.remove("active"));
            contents.forEach(c => c.classList.remove("active"));

            tab.classList.add("active");
            const targetElement = document.getElementById(target);
            if (targetElement) targetElement.classList.add("active");
            log_period_btn.style.display = "none";
        }
    });
});
