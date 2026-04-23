(async function bootstrapAdmin() {
  try {
    const user = await loadCurrentUser();

    if (!user) {
      document.getElementById("admin-warning").textContent = "Please log in first.";
      return;
    }

    const warning = document.getElementById("admin-warning");

    warning.textContent =
      user.role !== "admin"
        ? "Client says you're not admin (UI only)."
        : "Authenticated as admin.";

    const result = await api("/api/admin/users");

    const table = document.getElementById("admin-users");
    table.innerHTML = "";

    result.users.forEach((entry) => {
      const tr = document.createElement("tr");

      [entry.id, entry.username, entry.role, entry.displayName, entry.noteCount]
        .forEach((val) => {
          const td = document.createElement("td");
          td.textContent = val;
          tr.appendChild(td);
        });

      table.appendChild(tr);
    });

  } catch (error) {
    document.getElementById("admin-warning").textContent = error.message;
  }
})();