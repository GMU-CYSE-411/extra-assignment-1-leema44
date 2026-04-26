async function api(path, options = {}) {
  // FIXED CSRF: It reads the  the CSRF token from the cookie and attach it as a header on every request. 
  // The server will validate the  header against the cookie value
  function getCsrfToken() {
    const match = document.cookie
      .split("; ")
      .find((c) => c.startsWith("csrfToken="));
    return match ? match.split("=")[1] : "";
  }

  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": getCsrfToken(),     // FIX (CSRF)
      ...(options.headers || {})
    },
    credentials: "same-origin",
    ...options
  });

  const isJson = (response.headers.get("content-type") || "").includes("application/json");
  const body = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    const message =
      typeof body === "object" && body && body.error
        ? body.error
        : response.statusText;
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

// XSS issue here, Safe DOM escapes text before any innerHTML is actually inserted.
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = String(str ?? "");
  return div.innerHTML;
}