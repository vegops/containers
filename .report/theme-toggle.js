(() => {
  const storageKey = "vegops-report-theme";
  const preferences = ["light", "auto", "dark"];
  const root = document.documentElement;
  const button = document.getElementById("theme-toggle");
  const label = document.querySelector("[data-theme-label]");
  const track = button?.querySelector(".theme-toggle__track");
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  if (!button || !label) {
    return;
  }

  const capitalize = (value) => value.charAt(0).toUpperCase() + value.slice(1);

  const getStoredPreference = () => {
    try {
      const stored = window.localStorage.getItem(storageKey);
      return preferences.includes(stored) ? stored : "auto";
    } catch (_) {
      return "auto";
    }
  };

  const getEffectiveTheme = () =>
    getStoredPreference() === "auto" ? (media.matches ? "dark" : "light") : getStoredPreference();

  const getNextPreference = (preference) =>
    preferences[(preferences.indexOf(preference) + 1) % preferences.length];

  const persistPreference = (preference) => {
    try {
      if (preference === "auto") {
        window.localStorage.removeItem(storageKey);
      } else {
        window.localStorage.setItem(storageKey, preference);
      }
    } catch (_) {}
  };

  const syncRootTheme = () => {
    const preference = getStoredPreference();
    if (preference === "light" || preference === "dark") {
      root.dataset.theme = preference;
    } else {
      delete root.dataset.theme;
    }
  };

  const updateToggle = () => {
    const preference = getStoredPreference();
    const effective = getEffectiveTheme();
    const nextPref = getNextPreference(preference);

    button.dataset.themePreference = preference;
    button.setAttribute(
      "aria-label",
      preference === "auto"
        ? `Color theme: auto. Current system theme is ${effective}. Click to switch to ${nextPref}.`
        : `Color theme: ${preference}. Click to switch to ${nextPref}.`,
    );
    button.title =
      preference === "auto"
        ? `Following system theme (${effective}). Next: ${capitalize(nextPref)}.`
        : `Using ${preference} theme. Next: ${capitalize(nextPref)}.`;
    label.textContent = capitalize(preference);
  };

  const applyPreference = (preference) => {
    persistPreference(preference);
    syncRootTheme();
    updateToggle();
  };

  const switchTheme = (nextPreference) => {
    if (!document.startViewTransition || reducedMotion.matches) {
      applyPreference(nextPreference);
      return;
    }

    const rect = (track || button).getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    const radius = Math.hypot(
      Math.max(x, window.innerWidth - x),
      Math.max(y, window.innerHeight - y),
    );

    root.style.setProperty("--theme-transition-x", `${x}px`);
    root.style.setProperty("--theme-transition-y", `${y}px`);
    root.style.setProperty("--theme-transition-radius", `${radius}px`);

    document.startViewTransition(() => applyPreference(nextPreference));
  };

  syncRootTheme();
  updateToggle();

  button.addEventListener("click", () => {
    switchTheme(getNextPreference(getStoredPreference()));
  });

  const handleSystemChange = () => {
    if (getStoredPreference() === "auto") {
      syncRootTheme();
      updateToggle();
    }
  };

  if (typeof media.addEventListener === "function") {
    media.addEventListener("change", handleSystemChange);
  } else if (typeof media.addListener === "function") {
    media.addListener(handleSystemChange);
  }
})();
