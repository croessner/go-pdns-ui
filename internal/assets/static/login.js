(function () {
  "use strict";

  const root = document.documentElement;
  const themeController = window.__goPDNSUITheme || null;
  const allThemes = new Set(["light", "dark"]);

  function applyTheme(theme) {
    if (themeController && typeof themeController.applyTheme === "function") {
      return themeController.applyTheme(theme);
    }

    const resolvedTheme = allThemes.has(theme) ? theme : "light";
    root.setAttribute("data-theme", resolvedTheme);
    root.style.colorScheme = resolvedTheme;

    try {
      localStorage.setItem("go-pdns-ui-theme", resolvedTheme);
    } catch (_) {
      // Ignore storage failures (private mode/restrictions).
    }

    return resolvedTheme;
  }

  document.body.addEventListener("click", (event) => {
    const toggle = event.target.closest("#theme-toggle");
    if (!toggle) return;

    const current = root.getAttribute("data-theme") || "light";
    const next = current === "dark" ? "light" : "dark";
    applyTheme(next);
  });
})();
