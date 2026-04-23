function noteCard(note) {
  const article = document.createElement("article");
  article.className = "note-card";

  const title = document.createElement("h3");
  title.textContent = note.title;

  const meta = document.createElement("p");
  meta.className = "note-meta";
  meta.textContent = `Owner: ${note.ownerUsername} | ID: ${note.id} | Pinned: ${note.pinned}`;

  const body = document.createElement("div");
  body.className = "note-body";
  body.textContent = note.body;

  article.appendChild(title);
  article.appendChild(meta);
  article.appendChild(body);

  return article;
}

async function loadNotes(ownerId, search) {
  const query = new URLSearchParams();

  // SECURITY FIX: ignore client-controlled ownerId for access control
  // (server should enforce ownership via session anyway)
  if (search) {
    query.set("search", search);
  }

  const result = await api(`/api/notes?${query.toString()}`);
  const notesList = document.getElementById("notes-list");

  // SECURITY FIX: no innerHTML injection
  notesList.replaceChildren(...result.notes.map(noteCard));
}

(async function bootstrapNotes() {
  try {
    const user = await loadCurrentUser();

    if (!user) {
      document.getElementById("notes-list").textContent = "Please log in first.";
      return;
    }

    document.getElementById("notes-owner-id").value = user.id;
    document.getElementById("create-owner-id").value = user.id;

    // SECURITY FIX: do NOT pass ownerId from client
    await loadNotes(null, "");
  } catch (error) {
    document.getElementById("notes-list").textContent = error.message;
  }
})();

document.getElementById("search-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(event.currentTarget);

  // SECURITY FIX: ignore ownerId from user input
  await loadNotes(null, formData.get("search"));
});

document.getElementById("create-note-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(event.currentTarget);

  const payload = {
    // SECURITY FIX: do NOT allow client to set ownerId
    title: formData.get("title"),
    body: formData.get("body"),
    pinned: formData.get("pinned") === "on"
  };

  await api("/api/notes", {
    method: "POST",
    body: JSON.stringify(payload)
  });

  await loadNotes(null, "");
  event.currentTarget.reset();
});