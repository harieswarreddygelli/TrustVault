(() => {
    const root = document.documentElement;
    const STORAGE_KEY = "trustvault-theme";

    const SUN_ICON = `<svg xmlns="http://www.w3.org/2000/svg" width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42"/></svg>`;
    const MOON_ICON = `<svg xmlns="http://www.w3.org/2000/svg" width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20.985 12.486a9 9 0 1 1-9.473-9.472c.405-.022.617.463.402.807a6.5 6.5 0 0 0 8.268 8.268c.344-.215.829-.003.803.397"/></svg>`;

    function getPreferredTheme() {
        try {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored === "dark" || stored === "light") return stored;
        } catch (_) {}
        return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }

    function updateButtons(theme) {
        const isDark = theme === "dark";
        const buttons = document.querySelectorAll("#theme-toggle, .theme-toggle, .theme-switch");

        buttons.forEach((btn) => {
            btn.innerHTML = isDark ? SUN_ICON : MOON_ICON;
            btn.setAttribute("aria-label", isDark ? "Switch to light mode" : "Switch to dark mode");
            btn.title = isDark ? "Switch to light mode" : "Switch to dark mode";
        });
    }

    function applyTheme(value) {
        const theme = value === "dark" ? "dark" : "light";
        root.dataset.theme = theme;
        updateButtons(theme);
    }

    function toggleTheme() {
        const next = root.dataset.theme === "dark" ? "light" : "dark";
        applyTheme(next);
        try {
            localStorage.setItem(STORAGE_KEY, next);
        } catch (_) {}
    }

    // Apply immediately to prevent flash of unstyled theme
    applyTheme(getPreferredTheme());

    document.addEventListener("DOMContentLoaded", () => {
        const existingToggles = document.querySelectorAll("#theme-toggle, .theme-toggle, .theme-switch");

        if (existingToggles.length > 0) {
            existingToggles.forEach((btn) => {
                btn.addEventListener("click", toggleTheme);
            });
            updateButtons(root.dataset.theme);
            return;
        }

        // Fallback floating toggle for standalone pages without a header (Login/Register)
        const floatingBtn = document.createElement("button");
        floatingBtn.type = "button";
        floatingBtn.className = "theme-switch";
        document.body.appendChild(floatingBtn);

        floatingBtn.addEventListener("click", toggleTheme);
        updateButtons(root.dataset.theme);
    });
})();