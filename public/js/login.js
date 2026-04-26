// Session fixation needed, removed the setupFixationHelper block,
// It n read a session ID from the URL query string and wrote it into the sid cookie,
// which will allow a classic session fixation attack. 

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const payload = Object.fromEntries(formData.entries());
  try {
    const result = await api("/api/login", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    writeJson("login-output", result);
  } catch (error) {
    writeJson("login-output", { error: error.message });
  }
});