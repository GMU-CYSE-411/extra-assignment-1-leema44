async function loadSettings() {
  // Authorization issue here, userId is not passed as a query parameter, server derives it from the session. Sending ?userId=X was the client
  // side of the IDOR which will let any unauthorized user read any other user's settings that will exploit the confidentiality.
  const result = await api("/api/settings");
  const settings = result.settings;

  document.getElementById("settings-form-user-id").value = settings.userId;
  document.getElementById("settings-user-id").value = settings.userId;

  const form = document.getElementById("settings-form");
  form.elements.displayName.value = settings.displayName;
  form.elements.theme.value = settings.theme;
  form.elements.statusMessage.value = settings.statusMessage;
  form.elements.emailOptIn.checked = Boolean(settings.emailOptIn);

  // XSS fixed here:, innerHTML needed to be replaced with safe textContent displayName and statusMessage are user-controlled stored values — injecting
  const preview = document.getElementById("status-preview");
  preview.innerHTML = "";

  const namePara = document.createElement("p");
  const strong = document.createElement("strong");
  strong.textContent = settings.displayName;   //fixed
  namePara.appendChild(strong);

  const statusPara = document.createElement("p");
  statusPara.textContent = settings.statusMessage;   //fixed

  preview.appendChild(namePara);
  preview.appendChild(statusPara);

  writeJson("settings-output", settings);
}

(async function bootstrapSettings() {
  try {
    const user = await loadCurrentUser();
    if (!user) {
      writeJson("settings-output", { error: "Please log in first." });
      return;
    }
    await loadSettings();
  } catch (error) {
    writeJson("settings-output", { error: error.message });
  }
})();

// Authorization issue here, I removed the "query any user's settings by ID" form handler.
document.getElementById("settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const payload = {
    // FIX (Authorization): userId removed from payload — server uses the session.
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
  await loadSettings();
});

// CSRF problem here, I changed from api() GET call with query params to POST with body.
document.getElementById("enable-email").addEventListener("click", async () => {
  const result = await api("/api/settings/toggle-email", {
    method: "POST",
    body: JSON.stringify({ enabled: "1" })
  });
  writeJson("settings-output", result);
});

document.getElementById("disable-email").addEventListener("click", async () => {
  const result = await api("/api/settings/toggle-email", {
    method: "POST",
    body: JSON.stringify({ enabled: "0" })
  });
  writeJson("settings-output", result);
});