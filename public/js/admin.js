(async function bootstrapAdmin() {
  try {
    const user = await loadCurrentUser();
    if (!user) {
      document.getElementById("admin-warning").textContent = "Please log in first.";
      return;s
    }

    //Authorization fix needed, the page should not load the admin data when it's not an admin.
    if (user.role !== "admin") {
      document.getElementById("admin-warning").textContent =
        "Access denied. Admin only.";
      return;   // <-- was missing; non-admins fell through to the API call
    }

    document.getElementById("admin-warning").textContent = "Authenticated as admin.";

    const result = await api("/api/admin/users");

    // XSS issue was here. I  replaced innerHTML template literal with safe DOM so that it is not interpreted as HTML as a malicious user
    //could input something malicious and it would be executed as code.
    const tbody = document.getElementById("admin-users");
    tbody.innerHTML = "";

    result.users.forEach((entry) => {
      const tr = document.createElement("tr");
      [entry.id, entry.username, entry.role, entry.displayName, entry.noteCount]
        .forEach((val) => {
          const td = document.createElement("td");
          td.textContent = val ?? "";   
          tr.appendChild(td);
        });
      tbody.appendChild(tr);
    });

  } catch (error) {
    document.getElementById("admin-warning").textContent = error.message;
  }
})();