const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const { DEFAULT_DB_FILE, openDatabase } = require("../db");

function sendPublicFile(response, fileName) {
  response.sendFile(path.join(__dirname, "..", "public", fileName));
}

// FIXED: (Auth)- I Used crypto.randomBytes instead of Math.random for session IDs.
function createSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

async function createApp() {
  if (!fs.existsSync(DEFAULT_DB_FILE)) {
    throw new Error(
      `Database file not found at ${DEFAULT_DB_FILE}. Run "npm run init-db" first.`
    );
  }

  const db = openDatabase(DEFAULT_DB_FILE);
  const app = express();

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use("/css", express.static(path.join(__dirname, "..", "public", "css")));
  app.use("/js", express.static(path.join(__dirname, "..", "public", "js")));

  // FIXED (XSS issue)- Added Content-Security-Policy header to restrict execution of the context.
  app.use((_request, response, next) => {
    response.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; object-src 'none';"
    );
    next();
  });

  // CSRF token  —  it issues a token in a cookie and validates it on state-changing requests. This is the double-submit cookie pattern.
  app.use((request, response, next) => {
    // FIXED(CSRF): Issue a CSRF token if not already present.
    let csrfToken = request.cookies.csrfToken;
    if (!csrfToken) {
      csrfToken = crypto.randomBytes(32).toString("hex");
      // Not httpOnly so JS can read and send it in a header.
      response.cookie("csrfToken", csrfToken, {
        path: "/",
        sameSite: "Strict",
        secure: true
      });
    }

    // FIXED (CSRF): Validates CSRF token on all requests.
    const safeMethods = ["GET", "HEAD", "OPTIONS"];
    if (!safeMethods.includes(request.method)) {
      const tokenFromHeader = request.headers["x-csrf-token"];
      if (!tokenFromHeader || tokenFromHeader !== csrfToken) {
        response.status(403).json({ error: "Invalid CSRF token." });
        return;
      }
    }

    next();
  });

  app.use(async (request, response, next) => {
    const sessionId = request.cookies.sid;

    if (!sessionId) {
      request.currentUser = null;
      next();
      return;
    }

    const row = await db.get(
      `
        SELECT
          sessions.id AS session_id,
          users.id AS id,
          users.username AS username,
          users.role AS role,
          users.display_name AS display_name
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.id = ?
      `,
      [sessionId]
    );

    request.currentUser = row
      ? {
          sessionId: row.session_id,
          id: row.id,
          username: row.username,
          role: row.role,
          displayName: row.display_name
        }
      : null;

    next();
  });

  function requireAuth(request, response, next) {
    if (!request.currentUser) {
      response.status(401).json({ error: "Authentication required." });
      return;
    }
    next();
  }

  // FIXED authorization- Admin-only checks the role from the server-side session, not from anything the client submits.
  function requireAdmin(request, response, next) {
    if (!request.currentUser || request.currentUser.role !== "admin") {
      response.status(403).json({ error: "Forbidden." });
      return;
    }
    next();
  }

  app.get("/", (_request, response) => sendPublicFile(response, "index.html"));
  app.get("/login", (_request, response) => sendPublicFile(response, "login.html"));
  app.get("/notes", (_request, response) => sendPublicFile(response, "notes.html"));
  app.get("/settings", (_request, response) => sendPublicFile(response, "settings.html"));
  app.get("/admin", (_request, response) => sendPublicFile(response, "admin.html"));

  app.get("/api/me", (request, response) => {
    response.json({ user: request.currentUser });
  });

  app.post("/api/login", async (request, response) => {
    const username = String(request.body.username || "");
    const password = String(request.body.password || "");

    // FIXEd(Injection)- Parameterized query: username and password are passed as  values, not into the SQL string.
    const user = await db.get(
      `SELECT id, username, role, display_name
       FROM users
       WHERE username = ? AND password = ?`,
      [username, password]
    );

    if (!user) {
      response.status(401).json({ error: "Invalid username or password." });
      return;
    }

    // FIX (Auth — session fixation): Always invalidate any existing session before a new one. Never reuse a pre-login session ID.
    if (request.cookies.sid) {
      await db.run("DELETE FROM sessions WHERE id = ?", [request.cookies.sid]);
    }

    const sessionId = createSessionId();

    await db.run(
      "INSERT INTO sessions (id, user_id, created_at) VALUES (?, ?, ?)",
      [sessionId, user.id, new Date().toISOString()]
    );

    // FIXED (Auth): httpOnly prevents JS access; secure limits to HTTPS; sameSite: Strict provides CSRF defense at the cookie layer.
    response.cookie("sid", sessionId, {
      path: "/",
      httpOnly: true,
      secure: true,
      sameSite: "Strict"
    });

    response.json({
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        displayName: user.display_name
      }
    });
  });

  app.post("/api/logout", async (request, response) => {
    if (request.cookies.sid) {
      await db.run("DELETE FROM sessions WHERE id = ?", [request.cookies.sid]);
    }

    response.clearCookie("sid");
    response.json({ ok: true });
  });

  app.get("/api/notes", requireAuth, async (request, response) => {
    // FIX (Authorization): Ignore client-supplied ownerId entirely.
    // The owner is always the authenticated user from the session.
    const ownerId = request.currentUser.id;
    const search = request.query.search || "";

    // FIX (Injection): Both ownerId and search are now bound parameters.
    // Previously, ownerId was interpolated unquoted and search was inside
    // a LIKE string — both are classic injection vectors.
    const notes = await db.all(
      `SELECT
         notes.id,
         notes.owner_id AS ownerId,
         users.username AS ownerUsername,
         notes.title,
         notes.body,
         notes.pinned,
         notes.created_at AS createdAt
       FROM notes
       JOIN users ON users.id = notes.owner_id
       WHERE notes.owner_id = ?
         AND (notes.title LIKE ? OR notes.body LIKE ?)
       ORDER BY notes.pinned DESC, notes.id DESC`,
      [ownerId, `%${search}%`, `%${search}%`]
    );

    response.json({ notes });
  });

  app.post("/api/notes", requireAuth, async (request, response) => {
    // FIX (Authorization): Derive ownerId from the session, not the request body.
    // Previously an authenticated user could set ownerId to any user's ID.
    const ownerId = request.currentUser.id;
    const title = String(request.body.title || "");
    const body = String(request.body.body || "");
    const pinned = request.body.pinned ? 1 : 0;

    const result = await db.run(
      "INSERT INTO notes (owner_id, title, body, pinned, created_at) VALUES (?, ?, ?, ?, ?)",
      [ownerId, title, body, pinned, new Date().toISOString()]
    );

    response.status(201).json({ ok: true, noteId: result.lastID });
  });

  app.get("/api/settings", requireAuth, async (request, response) => {
    // FIX (Authorization): Derive userId from the session only.
    const userId = request.currentUser.id;

    const settings = await db.get(
      `SELECT
         users.id AS userId,
         users.username,
         users.role,
         users.display_name AS displayName,
         settings.status_message AS statusMessage,
         settings.theme,
         settings.email_opt_in AS emailOptIn
       FROM settings
       JOIN users ON users.id = settings.user_id
       WHERE settings.user_id = ?`,
      [userId]
    );

    response.json({ settings });
  });

  app.post("/api/settings", requireAuth, async (request, response) => {
    // FIX (Authorization): Derive userId from the session only.
    const userId = request.currentUser.id;
    const displayName = String(request.body.displayName || "");
    const statusMessage = String(request.body.statusMessage || "");
    const theme = String(request.body.theme || "classic");
    const emailOptIn = request.body.emailOptIn ? 1 : 0;

    await db.run("UPDATE users SET display_name = ? WHERE id = ?", [displayName, userId]);
    await db.run(
      "UPDATE settings SET status_message = ?, theme = ?, email_opt_in = ? WHERE user_id = ?",
      [statusMessage, theme, emailOptIn, userId]
    );

    response.json({ ok: true });
  });

  // FIX (CSRF): Changed from GET to POST. A GET endpoint that mutates state
  // can be triggered by a zero-click cross-origin resource load (e.g. <img src>).
  app.post("/api/settings/toggle-email", requireAuth, async (request, response) => {
    const enabled = request.body.enabled === "1" ? 1 : 0;

    // userId is derived from the session — no client input trusted.
    await db.run("UPDATE settings SET email_opt_in = ? WHERE user_id = ?", [
      enabled,
      request.currentUser.id
    ]);

    response.json({
      ok: true,
      userId: request.currentUser.id,
      emailOptIn: enabled
    });
  });

  // FIX (Authorization): requireAdmin enforces role from the server-side session.
  // Previously requireAuth alone allowed any authenticated user to access this.
  app.get("/api/admin/users", requireAuth, requireAdmin, async (_request, response) => {
    const users = await db.all(`
      SELECT
        users.id,
        users.username,
        users.role,
        users.display_name AS displayName,
        COUNT(notes.id) AS noteCount
      FROM users
      LEFT JOIN notes ON notes.owner_id = users.id
      GROUP BY users.id, users.username, users.role, users.display_name
      ORDER BY users.id
    `);

    response.json({ users });
  });

  return app;
}

module.exports = { createApp };