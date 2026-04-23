const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const { DEFAULT_DB_FILE, openDatabase } = require("../db");

function sendPublicFile(response, fileName) {
  response.sendFile(path.join(__dirname, "..", "public", fileName));
}

// FIX #5: Cryptographically secure session ID
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

  // Session middleware — unchanged logic, already used parameterized query
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

  // FIX #3: Role-based guard for admin routes
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

  // FIX #1: Parameterized query (no SQL injection)
  // FIX #4: bcrypt password comparison (no plaintext passwords)
  app.post("/api/login", async (request, response) => {
    const username = String(request.body.username || "");
    const password = String(request.body.password || "");

    const user = await db.get(
      "SELECT id, username, role, display_name, password AS passwordHash FROM users WHERE username = ?",
      [username]
    );

    // NOTE: This assumes passwords are stored as bcrypt hashes.
    // When creating users, hash passwords with: bcrypt.hash(plainPassword, 12)
    const passwordValid = user && await bcrypt.compare(password, user.passwordHash);

    if (!passwordValid) {
      response.status(401).json({ error: "Invalid username or password." });
      return;
    }

    // FIX #5: Use new secure session ID, never reuse attacker-supplied cookie value
    const sessionId = createSessionId();

    // Clean up any existing sessions for this user (optional: enforce single session)
    if (request.cookies.sid) {
      await db.run("DELETE FROM sessions WHERE id = ?", [request.cookies.sid]);
    }

    await db.run(
      "INSERT INTO sessions (id, user_id, created_at) VALUES (?, ?, ?)",
      [sessionId, user.id, new Date().toISOString()]
    );

    // FIX #6: Secure cookie flags
    response.cookie("sid", sessionId, {
      path: "/",
      httpOnly: true,   // Not accessible to JavaScript — mitigates XSS theft
      secure: true,     // Only sent over HTTPS
      sameSite: "strict" // Mitigates CSRF
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

  // FIX #1: Parameterized query (no SQL injection)
  // FIX #2: Enforce ownership — users can only query their own notes unless admin
  app.get("/api/notes", requireAuth, async (request, response) => {
    const isAdmin = request.currentUser.role === "admin";
    const requestedOwnerId = request.query.ownerId
      ? Number(request.query.ownerId)
      : request.currentUser.id;

    // Non-admins can only access their own notes
    if (!isAdmin && requestedOwnerId !== request.currentUser.id) {
      response.status(403).json({ error: "Forbidden." });
      return;
    }

    const ownerId = requestedOwnerId;
    const search = request.query.search || "";

    const notes = await db.all(
      `
        SELECT
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
        ORDER BY notes.pinned DESC, notes.id DESC
      `,
      [ownerId, `%${search}%`, `%${search}%`]
    );

    response.json({ notes });
  });

  // FIX #2: Enforce ownership — users can only create notes for themselves unless admin
  app.post("/api/notes", requireAuth, async (request, response) => {
    const isAdmin = request.currentUser.role === "admin";
    const requestedOwnerId = request.body.ownerId
      ? Number(request.body.ownerId)
      : request.currentUser.id;

    if (!isAdmin && requestedOwnerId !== request.currentUser.id) {
      response.status(403).json({ error: "Forbidden." });
      return;
    }

    const ownerId = requestedOwnerId;
    const title = String(request.body.title || "");
    const body = String(request.body.body || "");
    const pinned = request.body.pinned ? 1 : 0;

    const result = await db.run(
      "INSERT INTO notes (owner_id, title, body, pinned, created_at) VALUES (?, ?, ?, ?, ?)",
      [ownerId, title, body, pinned, new Date().toISOString()]
    );

    response.status(201).json({
      ok: true,
      noteId: result.lastID
    });
  });

  // FIX #2: Enforce ownership — users can only read their own settings unless admin
  app.get("/api/settings", requireAuth, async (request, response) => {
    const isAdmin = request.currentUser.role === "admin";
    const requestedUserId = request.query.userId
      ? Number(request.query.userId)
      : request.currentUser.id;

    if (!isAdmin && requestedUserId !== request.currentUser.id) {
      response.status(403).json({ error: "Forbidden." });
      return;
    }

    const userId = requestedUserId;

    const settings = await db.get(
      `
        SELECT
          users.id AS userId,
          users.username,
          users.role,
          users.display_name AS displayName,
          settings.status_message AS statusMessage,
          settings.theme,
          settings.email_opt_in AS emailOptIn
        FROM settings
        JOIN users ON users.id = settings.user_id
        WHERE settings.user_id = ?
      `,
      [userId]
    );

    response.json({ settings });
  });

  // FIX #2: Enforce ownership — users can only update their own settings unless admin
  app.post("/api/settings", requireAuth, async (request, response) => {
    const isAdmin = request.currentUser.role === "admin";
    const requestedUserId = request.body.userId
      ? Number(request.body.userId)
      : request.currentUser.id;

    if (!isAdmin && requestedUserId !== request.currentUser.id) {
      response.status(403).json({ error: "Forbidden." });
      return;
    }

    const userId = requestedUserId;
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

  // No ownership issue here — already uses session user ID only
  app.get("/api/settings/toggle-email", requireAuth, async (request, response) => {
    const enabled = request.query.enabled === "1" ? 1 : 0;

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

  // FIX #3: requireAdmin instead of just requireAuth
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

module.exports = {
  createApp
};