//XSS problem here, noteCard uses safe DOM construction instead of innerHTML, if a user inputes malicious content, it would be read in and interpreted.
function noteCard(note) {
  const article = document.createElement("article");
  article.className = "note-card";

  const heading = document.createElement("h3");
  heading.textContent = note.title;           // Fixed

  const meta = document.createElement("p");
  meta.className = "note-meta";
  meta.textContent = `Owner: ${note.ownerUsername} | ID: ${note.id} | Pinned: ${note.pinned}`;

  const body = document.createElement("div");
  body.className = "note-body";
  body.textContent = note.body;               // Fixed

  article.appendChild(heading);
  article.appendChild(meta);
  article.appendChild(body);

  return article;
}

// Auhorization fixed needd. I removed ownerId parameter removed which will allow the server to  ignore any
// client-supplied ownerId and uses the session, so we stop sending it.
async function loadNotes(search) {
  const query = new URLSearchParams();
  if (search) {
    query.set("search", search);
  }
  const result = await api(`/api/notes?${query.toString()}`);
  const notesList = document.getElementById("notes-list");

  // XSS issue here, I replacedinnerHTML with safe DOM node appending
  notesList.innerHTML = "";
  result.notes.forEach((note) => notesList.appendChild(noteCard(note)));
}

(async function bootstrapNotes() {
  try {
    const user = await loadCurrentUser();
    if (!user) {
      document.getElementById("notes-list").textContent = "Please log in first.";
      return;
    }
    // Authorization fixed required, it won't expose an ownerId input
    await loadNotes("");
  } catch (error) {
    document.getElementById("notes-list").textContent = error.message;
  }
})();

document.getElementById("search-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  // Authorization fixed here, it will only pass search and ownerId field is removed from the form flow.
  await loadNotes(formData.get("search"));
});

document.getElementById("create-note-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const payload = {
    //FIX Authorization, ownerId is no longer sent in the POST body. The server will derive it from the session directly
    title: formData.get("title"),
    body: formData.get("body"),
    pinned: formData.get("pinned") === "on"
  };
  await api("/api/notes", {
    method: "POST",
    body: JSON.stringify(payload)
  });
  await loadNotes("");
  event.currentTarget.reset();
});