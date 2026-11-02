require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || ("http://localhost:" + PORT)).replace(/\/$/, "");
const DATA_DIR = path.resolve(process.env.DATA_DIR || "./data");
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, "purplecreator.sqlite"));
db.pragma("journal_mode = WAL");
db.exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT NOT NULL UNIQUE COLLATE NOCASE,password_hash TEXT NOT NULL,display_name TEXT NOT NULL,hf_username TEXT,hf_token_enc TEXT,hf_token_iv TEXT,hf_token_tag TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS models (id TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,base_model TEXT NOT NULL,dataset_id TEXT NOT NULL,gpu TEXT NOT NULL,device TEXT NOT NULL,ram_gb INTEGER NOT NULL,examples INTEGER NOT NULL,hf_repo TEXT,status TEXT NOT NULL DEFAULT 'configured',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS chat_messages (id INTEGER PRIMARY KEY AUTOINCREMENT,model_id TEXT NOT NULL REFERENCES models(id) ON DELETE CASCADE,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,role TEXT NOT NULL,content TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);");

const appSecret = process.env.SESSION_SECRET;
if (process.env.NODE_ENV === "production" && (!appSecret || appSecret.length < 32)) {
  console.error("SESSION_SECRET must be at least 32 characters in production.");
  process.exit(1);
}
const encryptionKey = process.env.TOKEN_ENCRYPTION_KEY || "";
function encryptionReady() { return /^[a-f0-9]{64}$/i.test(encryptionKey); }
function encrypt(value) {
  if (!encryptionReady()) throw new Error("TOKEN_ENCRYPTION_KEY is not configured (64 hex characters required).");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(encryptionKey, "hex"), iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return { data: encrypted.toString("base64"), iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64") };
}
function decrypt(row) {
  if (!encryptionReady()) throw new Error("Token encryption is not configured.");
  const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(encryptionKey, "hex"), Buffer.from(row.hf_token_iv, "base64"));
  decipher.setAuthTag(Buffer.from(row.hf_token_tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(row.hf_token_enc, "base64")), decipher.final()]).toString("utf8");
}
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR, table: "sessions" }),
  secret: appSecret || "development-only-change-this-secret",
  resave: false, saveUninitialized: false, name: "purplecreator.sid",
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: "draft-7", legacyHeaders: false }));
app.use("/auth/huggingface", rateLimit({ windowMs: 15 * 60 * 1000, limit: 20 }));
app.use((req, res, next) => {
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && req.path.startsWith("/api/")) {
    const origin = req.get("origin");
    if (origin && origin !== BASE_URL) return res.status(403).json({ error: "Nieprawidłowe źródło żądania." });
  }
  next();
});
const publicUser = u => ({ id: u.id, email: u.email, name: u.display_name, hfUsername: u.hf_username || null, hfConnected: Boolean(u.hf_token_enc) });
const getUser = req => req.session.userId ? db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId) : null;
function requireAuth(req, res, next) {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: "Zaloguj się, aby kontynuować." });
  req.user = user; next();
}
function cleanString(v, max=160) { return typeof v === "string" ? v.trim().slice(0,max) : ""; }

app.get("/.well-known/oauth-cimd", (req, res) => {
  res.json({
    client_id: BASE_URL + "/.well-known/oauth-cimd",
    client_name: "PurpleCreator",
    redirect_uris: [BASE_URL + "/auth/huggingface/callback"],
    token_endpoint_auth_method: "none",
    client_uri: BASE_URL
  });
});
app.post("/api/auth/register", (req, res) => {
  const email = cleanString(req.body.email, 254).toLowerCase();
  const name = cleanString(req.body.name, 40);
  const password = typeof req.body.password === "string" ? req.body.password : "";
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Podaj prawidłowy adres e-mail." });
  if (password.length < 10 || password.length > 72) return res.status(400).json({ error: "Hasło musi mieć od 10 do 72 znaków." });
  if (name.length < 2) return res.status(400).json({ error: "Nazwa musi mieć co najmniej 2 znaki." });
  try {
    const hash = bcrypt.hashSync(password, 12);
    const info = db.prepare("INSERT INTO users(email,password_hash,display_name) VALUES(?,?,?)").run(email, hash, name);
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "Nie udało się utworzyć sesji." });
      req.session.userId = Number(info.lastInsertRowid);
      res.status(201).json({ user: publicUser(getUser(req)) });
    });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) return res.status(409).json({ error: "Konto z tym adresem e-mail już istnieje." });
    res.status(500).json({ error: "Nie udało się utworzyć konta." });
  }
});
app.post("/api/auth/login", (req, res) => {
  const email = cleanString(req.body.email, 254).toLowerCase();
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: "Nieprawidłowy e-mail lub hasło." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Nie udało się rozpocząć sesji." });
    req.session.userId = user.id;
    res.json({ user: publicUser(user) });
  });
});
app.post("/api/auth/logout", (req, res) => req.session.destroy(() => { res.clearCookie("purplecreator.sid"); res.json({ ok: true }); }));
app.get("/api/auth/me", (req, res) => { const user = getUser(req); res.json({ user: user ? publicUser(user) : null }); });

app.get("/auth/huggingface/start", requireAuth, (req, res) => {
  const state = crypto.randomBytes(24).toString("hex");
  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  req.session.hfOAuth = { state, verifier, created: Date.now() };
  const params = new URLSearchParams({
    client_id: BASE_URL + "/.well-known/oauth-cimd",
    redirect_uri: BASE_URL + "/auth/huggingface/callback",
    response_type: "code", scope: "openid profile", state,
    code_challenge: challenge, code_challenge_method: "S256"
  });
  res.redirect("https://huggingface.co/oauth/authorize?" + params.toString());
});
app.get("/auth/huggingface/callback", requireAuth, async (req, res) => {
  const saved = req.session.hfOAuth;
  delete req.session.hfOAuth;
  if (!saved || Date.now() - saved.created > 600000 || req.query.state !== saved.state || !req.query.code) return res.redirect("/?hf=error");
  try {
    const body = new URLSearchParams({
      grant_type: "authorization_code", code: String(req.query.code),
      client_id: BASE_URL + "/.well-known/oauth-cimd",
      redirect_uri: BASE_URL + "/auth/huggingface/callback", code_verifier: saved.verifier
    });
    const tokenResponse = await fetch("https://huggingface.co/oauth/token", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body
    });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.access_token) throw new Error("Token exchange failed");
    const infoResponse = await fetch("https://huggingface.co/oauth/userinfo", { headers: { Authorization: "Bearer " + tokenData.access_token } });
    let info = await infoResponse.json();
    if (!infoResponse.ok) {
      const fallback = await fetch("https://huggingface.co/api/whoami-v2", { headers: { Authorization: "Bearer " + tokenData.access_token } });
      info = await fallback.json();
      if (!fallback.ok) throw new Error("Could not read HF profile");
    }
    const username = cleanString(info.preferred_username || info.name || info.sub, 80);
    const encrypted = encrypt(tokenData.access_token);
    db.prepare("UPDATE users SET hf_username=?,hf_token_enc=?,hf_token_iv=?,hf_token_tag=? WHERE id=?")
      .run(username, encrypted.data, encrypted.iv, encrypted.tag, req.user.id);
    res.redirect("/?hf=connected");
  } catch (e) {
    console.error("Hugging Face OAuth error:", e.message);
    res.redirect("/?hf=error");
  }
});
app.get("/api/huggingface/status", requireAuth, (req, res) => res.json({ connected: Boolean(req.user.hf_token_enc), username: req.user.hf_username || null }));
app.post("/api/huggingface/disconnect", requireAuth, (req, res) => {
  db.prepare("UPDATE users SET hf_username=NULL,hf_token_enc=NULL,hf_token_iv=NULL,hf_token_tag=NULL WHERE id=?").run(req.user.id);
  res.json({ connected: false });
});

app.get("/api/models", requireAuth, (req, res) => {
  const models = db.prepare("SELECT id,name,base_model,dataset_id,gpu,device,ram_gb,examples,hf_repo,status,created_at FROM models WHERE user_id=? ORDER BY created_at DESC").all(req.user.id);
  res.json({ models });
});
app.post("/api/models", requireAuth, (req, res) => {
  if (!req.user.hf_token_enc) return res.status(409).json({ error: "Najpierw połącz konto Hugging Face." });
  const name = cleanString(req.body.name, 48);
  const base = cleanString(req.body.baseModel, 180);
  const dataset = cleanString(req.body.datasetId, 180);
  const gpu = cleanString(req.body.gpu, 80);
  const device = req.body.device === "laptop" ? "laptop" : "desktop";
  const ram = Number(req.body.ram);
  const examples = Number(req.body.examples);
  if (name.length < 2 || !/^[\w.-]+\/[\w.-]+$/.test(base) || !/^[\w.-]+\/[\w.-]+$/.test(dataset))
    return res.status(400).json({ error: "Podaj nazwę, prawidłowy model bazowy i ID datasetu w formacie autor/nazwa." });
  if (!Number.isInteger(ram) || ram < 4 || ram > 512 || !Number.isInteger(examples) || examples < 40000 || examples > 200000)
    return res.status(400).json({ error: "Nieprawidłowe ustawienia RAM lub liczby przykładów." });
  const id = crypto.randomUUID();
  const repo = req.user.hf_username + "/" + name.toLowerCase().replace(/[^a-z0-9.-]+/g,"-").replace(/^-|-$/g,"") + "-purplecreator";
  db.prepare("INSERT INTO models(id,user_id,name,base_model,dataset_id,gpu,device,ram_gb,examples,hf_repo) VALUES(?,?,?,?,?,?,?,?,?,?)")
    .run(id, req.user.id, name, base, dataset, gpu, device, ram, examples, repo);
  res.status(201).json({ model: db.prepare("SELECT id,name,base_model,dataset_id,gpu,device,ram_gb,examples,hf_repo,status,created_at FROM models WHERE id=?").get(id) });
});
app.delete("/api/models/:id", requireAuth, (req, res) => {
  const result = db.prepare("DELETE FROM models WHERE id=? AND user_id=?").run(req.params.id, req.user.id);
  if (!result.changes) return res.status(404).json({ error: "Nie znaleziono modelu." });
  res.json({ ok: true });
});
app.get("/api/models/:id/messages", requireAuth, (req, res) => {
  const model = db.prepare("SELECT id FROM models WHERE id=? AND user_id=?").get(req.params.id, req.user.id);
  if (!model) return res.status(404).json({ error: "Nie znaleziono modelu." });
  const messages = db.prepare("SELECT role,content,created_at FROM chat_messages WHERE model_id=? AND user_id=? ORDER BY id DESC LIMIT 40").all(model.id, req.user.id).reverse();
  res.json({ messages });
});
app.post("/api/models/:id/chat", requireAuth, async (req, res) => {
  const model = db.prepare("SELECT * FROM models WHERE id=? AND user_id=?").get(req.params.id, req.user.id);
  if (!model) return res.status(404).json({ error: "Nie znaleziono modelu." });
  if (!model.hf_repo) return res.status(409).json({ error: "Model nie ma jeszcze repozytorium Hugging Face." });
  const message = cleanString(req.body.message, 4000);
  if (!message) return res.status(400).json({ error: "Wpisz wiadomość." });
  try {
    const token = decrypt(req.user);
    const history = db.prepare("SELECT role,content FROM chat_messages WHERE model_id=? AND user_id=? ORDER BY id DESC LIMIT 10").all(model.id, req.user.id).reverse();
    const response = await fetch("https://router.huggingface.co/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
      body: JSON.stringify({ model: model.hf_repo, messages: [...history, { role: "user", content: message }], max_tokens: 500, stream: false })
    });
    const data = await response.json();
    if (!response.ok) return res.status(502).json({ error: data.error?.message || "Hugging Face nie udostępnił odpowiedzi. Sprawdź dostępność modelu i uprawnienia konta." });
    const answer = data.choices?.[0]?.message?.content;
    if (!answer) return res.status(502).json({ error: "Model zwrócił pustą odpowiedź." });
    const save = db.prepare("INSERT INTO chat_messages(model_id,user_id,role,content) VALUES(?,?,?,?)");
    save.run(model.id, req.user.id, "user", message);
    save.run(model.id, req.user.id, "assistant", String(answer).slice(0,12000));
    res.json({ answer });
  } catch (e) {
    console.error("Chat error:", e.message);
    res.status(500).json({ error: "Nie udało się połączyć z modelem. Sprawdź konfigurację szyfrowania tokenu." });
  }
});
app.get("/api/health", (req, res) => res.json({ ok: true, service: "PurpleCreator", version: "1.0.0" }));
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.listen(PORT, () => console.log("PurpleCreator running on port " + PORT));
