async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    credentials: "same-origin",
    ...options
  });

  const isJson = (response.headers.get("content-type") || "").includes("application/json");
  const body = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    const message = typeof body === "object" && body && body.error ? body.error : response.statusText;
    throw new Error(message);
  }

  return body;
}

async function loadCurrentUser() {
  const data = await api("/api/me");
  return data.user;
}

function writeJson(elementId, value) {
  const target = document.getElementById(elementId);

  if (target) {
    target.textContent = JSON.stringify(value, null, 2);
  }
}

async function loadSettings(userId) {
  const result = await api(`/api/settings?userId=${encodeURIComponent(userId)}`);
  const settings = result.settings;

  // NOTE: userId inputs are kept for display/reference only.
  // The server ignores the userId in POST bodies and uses the session instead.
  document.getElementById("settings-form-user-id").value = settings.userId;
  document.getElementById("settings-user-id").value = settings.userId;

  const form = document.getElementById("settings-form");
  form.elements.displayName.value = settings.displayName;
  form.elements.theme.value = settings.theme;
  form.elements.statusMessage.value = settings.statusMessage;
  form.elements.emailOptIn.checked = Boolean(settings.emailOptIn);

  // FIX: XSS — replaced innerHTML interpolation with safe DOM construction.
  // Previously: innerHTML = `...<p>${settings.statusMessage}</p>...`
  // An attacker could store malicious HTML/JS in displayName or statusMessage
  // and have it execute in every viewer's browser (stored XSS).
  const preview = document.getElementById("status-preview");

  const nameEl = document.createElement("p");
  const nameStrong = document.createElement("strong");
  nameStrong.textContent = settings.displayName; // .textContent escapes all HTML
  nameEl.appendChild(nameStrong);

  const statusEl = document.createElement("p");
  statusEl.textContent = settings.statusMessage; // .textContent escapes all HTML

  preview.replaceChildren(nameEl, statusEl);

  writeJson("settings-output", settings);
}

(async function bootstrapSettings() {
  try {
    const user = await loadCurrentUser();

    if (!user) {
      writeJson("settings-output", { error: "Please log in first." });
      return;
    }

    // FIX: IDOR — store the current user on the window so we can reference
    // their role throughout the page without re-fetching.
    window.__currentUser = user;

    // FIX: IDOR — hide the admin-only "query by userId" form for non-admins.
    // Regular users have no legitimate reason to load another user's settings.
    const queryForm = document.getElementById("settings-query-form");
    if (queryForm) {
      queryForm.style.display = user.role === "admin" ? "" : "none";
    }

    await loadSettings(user.id);
  } catch (error) {
    writeJson("settings-output", { error: error.message });
  }
})();

// FIX: IDOR — only admins should be able to reach this form (it's hidden above
// for non-admins), but guard here too in case the DOM is manipulated.
document.getElementById("settings-query-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  if (window.__currentUser?.role !== "admin") {
    writeJson("settings-output", { error: "Forbidden." });
    return;
  }

  const formData = new FormData(event.currentTarget);
  await loadSettings(formData.get("userId"));
});

document.getElementById("settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(event.currentTarget);

  // FIX: Don't send userId in the POST payload at all — the server derives the
  // target user from the session. Sending it as a hidden field allowed anyone
  // to tamper with it in DevTools and overwrite another user's settings
  // (assuming a vulnerable server; our fixed server ignores it anyway).
  const payload = {
    displayName: formData.get("displayName"),
    theme: formData.get("theme"),
    statusMessage: formData.get("statusMessage"),
    emailOptIn: formData.get("emailOptIn") === "on"
  };

  const result = await api("/api/settings", {
    method: "POST",
    body: JSON.stringify(payload)
  });

  writeJson("settings-output", result);

  // Reload using the current user's own ID, not a potentially tampered form value
  await loadSettings(window.__currentUser.id);
});

document.getElementById("enable-email").addEventListener("click", async () => {
  const result = await api("/api/settings/toggle-email?enabled=1");
  writeJson("settings-output", result);
});

document.getElementById("disable-email").addEventListener("click", async () => {
  const result = await api("/api/settings/toggle-email?enabled=0");
  writeJson("settings-output", result);
});