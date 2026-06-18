import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import QRCode from "qrcode";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
const PRIVATE_KEY_FILE = path.join(DATA_DIR, "license-private.pem");
const PUBLIC_KEY_FILE = path.join(DATA_DIR, "license-public.pem");
const ENV_FILE = path.join(__dirname, ".env");

loadEnv();

const PORT = Number(process.env.PORT || 3080);
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const SETUP_TOKEN = process.env.SETUP_TOKEN || "";
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "false").toLowerCase() === "true";
const LICENSE_GRACE_HOURS = Number(process.env.LICENSE_GRACE_HOURS || 48);
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * Number(process.env.SESSION_DAYS || 30);
const sessions = new Map();

ensureStorage();
const keys = ensureKeys();
let db = loadDb();
loadSessions();

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", APP_URL);
    if (req.method === "GET" && url.pathname === "/assets/app.css") return css(res);
    if (req.method === "GET" && url.pathname === "/health") return json(res, 200, { ok: true });
    if (req.method === "POST" && url.pathname === "/api/v1/license/check") return apiCheck(req, res);
    if (req.method === "GET" && url.pathname === "/setup") return setupPage(req, res, url);
    if (req.method === "POST" && url.pathname === "/setup") return setupSubmit(req, res, url);
    if (req.method === "GET" && url.pathname === "/login") return loginPage(req, res);
    if (req.method === "POST" && url.pathname === "/login") return loginSubmit(req, res);
    if (req.method === "POST" && url.pathname === "/logout") return logout(req, res);

    const user = requireAuth(req, res);
    if (!user) return;

    if (req.method === "GET" && url.pathname === "/") return redirect(res, "/admin");
    if (req.method === "GET" && url.pathname === "/admin") return adminHome(req, res, user);
    if (req.method === "GET" && url.pathname === "/admin/products") return productsPage(req, res, user);
    if (req.method === "POST" && url.pathname === "/admin/products") return productsSubmit(req, res, user);
    if (req.method === "GET" && url.pathname === "/admin/licenses") return licensesPage(req, res, user);
    if (req.method === "POST" && url.pathname === "/admin/licenses") return licensesSubmit(req, res, user);
    if (req.method === "GET" && url.pathname === "/admin/activations") return activationsPage(req, res, user);
    if (req.method === "POST" && url.pathname === "/admin/activations") return activationsSubmit(req, res, user);
    if (req.method === "GET" && url.pathname === "/admin/public-key") return publicKeyPage(req, res, user);

    return page(res, 404, "Nie znaleziono", card("Nie znaleziono", "<p>Ta strona nie istnieje.</p>"), user);
  } catch (error) {
    console.error(error);
    return page(res, 500, "Blad", card("Blad serwera", `<p>${escapeHtml(error.message)}</p>`));
  }
});

server.listen(PORT, () => {
  console.log(`Panel licencji dziala: http://localhost:${PORT}`);
  if (!db.users.length) {
    console.log(`Pierwsza konfiguracja: http://localhost:${PORT}/setup?token=${SETUP_TOKEN || "USTAW_SETUP_TOKEN_W_ENV"}`);
  }
});

function loadEnv() {
  if (!fs.existsSync(ENV_FILE)) return;
  for (const line of fs.readFileSync(ENV_FILE, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const index = trimmed.indexOf("=");
    if (index <= 0) continue;
    const key = trimmed.slice(0, index).trim();
    const value = trimmed.slice(index + 1).trim().replace(/^["']|["']$/g, "");
    process.env[key] = value;
  }
}

function ensureStorage() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function ensureKeys() {
  if (!fs.existsSync(PRIVATE_KEY_FILE) || !fs.existsSync(PUBLIC_KEY_FILE)) {
    const pair = crypto.generateKeyPairSync("rsa", { modulusLength: 3072 });
    fs.writeFileSync(PRIVATE_KEY_FILE, pair.privateKey.export({ type: "pkcs8", format: "pem" }));
    fs.writeFileSync(PUBLIC_KEY_FILE, pair.publicKey.export({ type: "spki", format: "pem" }));
  }
  return {
    privateKey: fs.readFileSync(PRIVATE_KEY_FILE, "utf8"),
    publicKey: fs.readFileSync(PUBLIC_KEY_FILE, "utf8")
  };
}

function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    return {
      users: [],
      products: [{ id: "mobcash", name: "MobCash Core", active: true, createdAt: nowIso() }],
      licenses: [],
      activations: [],
      checks: []
    };
  }
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function saveDb() {
  const tmp = `${DB_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

function loadSessions() {
  if (!fs.existsSync(SESSIONS_FILE)) return;
  try {
    const raw = JSON.parse(fs.readFileSync(SESSIONS_FILE, "utf8"));
    for (const [sid, session] of Object.entries(raw)) {
      if (session && Number(session.expiresAt) > Date.now()) {
        sessions.set(sid, session);
      }
    }
  } catch (error) {
    console.warn("Nie udalo sie wczytac sesji:", error.message);
  }
}

function saveSessions() {
  const now = Date.now();
  const data = {};
  for (const [sid, session] of sessions.entries()) {
    if (session.expiresAt > now) {
      data[sid] = session;
    }
  }
  const tmp = `${SESSIONS_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, SESSIONS_FILE);
}

async function setupPage(req, res, url) {
  if (db.users.length) return redirect(res, "/login");
  if (!SETUP_TOKEN || url.searchParams.get("token") !== SETUP_TOKEN) {
    return page(res, 403, "Setup", card("Setup zablokowany", "<p>Ustaw poprawny SETUP_TOKEN i wejdz z tokenem.</p>"));
  }
  const secret = base32Random();
  const csrf = issueCsrf(req, res);
  const qr = await QRCode.toDataURL(otpauth("MobCash Licencje", secret), {
    errorCorrectionLevel: "M",
    margin: 2,
    width: 220,
    color: {
      dark: "#071018",
      light: "#ffffff"
    }
  });
  const body = card("Pierwszy admin", `
    <form method="post" action="/setup?token=${escapeHtml(SETUP_TOKEN)}" class="form-grid">
      ${hidden("csrf", csrf)}
      ${hidden("secret", secret)}
      <input type="hidden" name="token" value="${escapeHtml(SETUP_TOKEN)}">
      <label>Email<input name="email" type="email" required autocomplete="email"></label>
      <label>Haslo<input name="password" type="password" minlength="10" required autocomplete="new-password"></label>
      <div class="notice">
        <strong>2FA wymagane.</strong>
        <span>Zeskanuj QR w aplikacji 2FA albo wpisz sekret recznie, potem podaj aktualny kod.</span>
        <img class="qr" src="${qr}" alt="Kod QR 2FA">
        <code>${secret}</code>
        <small>${escapeHtml(otpauth("MobCash Licencje", secret))}</small>
      </div>
      <label>Kod 2FA<input name="totp" inputmode="numeric" pattern="[0-9]{6}" required></label>
      <button class="primary">Utworz admina</button>
    </form>
  `);
  return page(res, 200, "Setup", body);
}

async function setupSubmit(req, res, url) {
  if (db.users.length) return redirect(res, "/login");
  const form = await parseForm(req);
  const token = String(form.token || url.searchParams.get("token") || "");
  if (!SETUP_TOKEN || token !== SETUP_TOKEN) return forbidden(res);
  const email = String(form.email || "").toLowerCase().trim();
  const password = String(form.password || "");
  const secret = String(form.secret || "");
  if (!email || password.length < 10 || !verifyTotp(secret, String(form.totp || ""))) {
    return page(res, 400, "Setup", card("Niepoprawne dane", "<p>Sprawdz email, haslo i kod 2FA.</p>"));
  }
  db.users.push({
    id: id("usr"),
    email,
    passwordHash: await hashPassword(password),
    totpSecret: secret,
    role: "owner",
    createdAt: nowIso()
  });
  saveDb();
  return redirect(res, "/login");
}

function loginPage(req, res) {
  const csrf = issueCsrf(req, res);
  return page(res, 200, "Logowanie", card("Panel licencji", `
    <form method="post" class="form-grid">
      ${hidden("csrf", csrf)}
      <label>Email<input name="email" type="email" required autocomplete="email"></label>
      <label>Haslo<input name="password" type="password" required autocomplete="current-password"></label>
      <label>Kod 2FA<input name="totp" inputmode="numeric" pattern="[0-9]{6}" required autocomplete="one-time-code"></label>
      <button class="primary">Zaloguj</button>
    </form>
  `));
}

async function loginSubmit(req, res) {
  const form = await parseForm(req);
  const user = db.users.find(u => u.email === String(form.email || "").toLowerCase().trim());
  if (!user || !(await verifyPassword(String(form.password || ""), user.passwordHash)) || !verifyTotp(user.totpSecret, String(form.totp || ""))) {
    return page(res, 401, "Logowanie", card("Nie zalogowano", "<p>Email, haslo albo kod 2FA sa niepoprawne.</p>"));
  }
  const sid = id("ses");
  sessions.set(sid, { userId: user.id, csrf: randomHex(24), expiresAt: Date.now() + SESSION_TTL_MS });
  saveSessions();
  setCookie(res, "sid", sid, SESSION_TTL_MS / 1000);
  return redirect(res, "/admin");
}

function logout(req, res) {
  const sid = cookies(req).sid;
  if (sid) sessions.delete(sid);
  saveSessions();
  setCookie(res, "sid", "", 0);
  return redirect(res, "/login");
}

function adminHome(req, res, user) {
  const pending = db.activations.filter(a => a.status === "pending").length;
  const active = db.licenses.filter(l => l.status === "active").length;
  const body = `
    <section class="hero">
      <div>
        <p class="eyebrow">MobCash License Center</p>
        <h1>Kontrola licencji i serwerow</h1>
        <p>Jedna licencja moze dzialac tylko na zaakceptowanym serwerze. Nowe proby odpalenia wpadaja tutaj jako oczekujace.</p>
      </div>
      <div class="metrics">
        ${metric("Aktywne licencje", active)}
        ${metric("Do akceptacji", pending)}
        ${metric("Paczki", db.products.length)}
      </div>
    </section>
    <div class="grid two">
      ${card("Szybkie akcje", `
        <div class="actions">
          <a class="button" href="/admin/licenses">Licencje</a>
          <a class="button" href="/admin/activations">Serwery</a>
          <a class="button" href="/admin/products">Paczki</a>
          <a class="button" href="/admin/public-key">Klucz publiczny</a>
        </div>
      `)}
      ${card("Ostatnie sprawdzenia", table(["Czas", "Licencja", "Serwer", "Status"], db.checks.slice(-8).reverse().map(c => [
        fmtDate(c.createdAt), c.licenseKey || "-", c.serverId || "-", badge(c.status)
      ])))}
    </div>`;
  return page(res, 200, "Panel", body, user);
}

function productsPage(req, res, user) {
  const csrf = issueCsrf(req, res);
  const rows = db.products.map(p => [
    p.id,
    p.name,
    badge(p.active ? "active" : "disabled"),
    formButton(csrf, "/admin/products", { action: "toggle", id: p.id }, p.active ? "Wylacz" : "Wlacz")
  ]);
  const body = card("Paczki", `
    ${table(["ID", "Nazwa", "Status", ""], rows)}
    <form method="post" class="form-grid inline">
      ${hidden("csrf", csrf)}
      ${hidden("action", "create")}
      <label>ID<input name="id" placeholder="np. mobcash"></label>
      <label>Nazwa<input name="name" placeholder="MobCash Core"></label>
      <button class="primary">Dodaj paczke</button>
    </form>
  `);
  return page(res, 200, "Paczki", body, user);
}

async function productsSubmit(req, res) {
  const form = await parseForm(req);
  if (!validCsrf(req, form.csrf)) return forbidden(res);
  if (form.action === "create") {
    const productId = normalizeId(form.id);
    if (productId && !db.products.some(p => p.id === productId)) {
      db.products.push({ id: productId, name: String(form.name || productId), active: true, createdAt: nowIso() });
      saveDb();
    }
  }
  if (form.action === "toggle") {
    const product = db.products.find(p => p.id === form.id);
    if (product) {
      product.active = !product.active;
      saveDb();
    }
  }
  return redirect(res, "/admin/products");
}

function licensesPage(req, res, user) {
  const csrf = issueCsrf(req, res);
  const products = db.products.map(p => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join("");
  const rows = db.licenses.map(l => [
    `<code>${escapeHtml(l.key)}</code>`,
    escapeHtml(productName(l.productId)),
    escapeHtml(l.owner || "-"),
    badge(l.status),
    fmtDate(l.expiresAt) || "bezterminowo",
    `<div class="row-actions">
      ${formButton(csrf, "/admin/licenses", { action: "status", id: l.id, status: l.status === "active" ? "disabled" : "active" }, l.status === "active" ? "Wylacz" : "Wlacz")}
      ${formButton(csrf, "/admin/licenses", { action: "detach", id: l.id }, "Odlacz serwer")}
      ${formButton(csrf, "/admin/licenses", { action: "delete", id: l.id }, "Usun", "danger")}
    </div>`
  ]);
  const body = card("Licencje", `
    <form method="post" class="form-grid inline">
      ${hidden("csrf", csrf)}
      ${hidden("action", "create")}
      <label>Paczka<select name="productId">${products}</select></label>
      <label>Klient<input name="owner" placeholder="email/nick klienta"></label>
      <label>Wazna do<input name="expiresAt" type="date"></label>
      <button class="primary">Utworz licencje</button>
    </form>
    ${table(["Klucz", "Paczka", "Klient", "Status", "Wazna do", ""], rows)}
  `);
  return page(res, 200, "Licencje", body, user);
}

async function licensesSubmit(req, res) {
  const form = await parseForm(req);
  if (!validCsrf(req, form.csrf)) return forbidden(res);
  const license = db.licenses.find(l => l.id === form.id);
  if (form.action === "create") {
    const product = db.products.find(p => p.id === form.productId);
    if (product) {
      db.licenses.push({
        id: id("lic"),
        key: licenseKey(product.id),
        productId: product.id,
        owner: String(form.owner || "").trim(),
        status: "active",
        expiresAt: form.expiresAt ? new Date(`${form.expiresAt}T23:59:59.000Z`).toISOString() : "",
        createdAt: nowIso()
      });
      saveDb();
    }
  } else if (license && form.action === "status") {
    license.status = form.status === "active" ? "active" : "disabled";
    saveDb();
  } else if (license && form.action === "detach") {
    for (const activation of db.activations.filter(a => a.licenseId === license.id && a.status === "approved")) {
      activation.status = "detached";
      activation.updatedAt = nowIso();
    }
    saveDb();
  } else if (license && form.action === "delete") {
    license.status = "deleted";
    for (const activation of db.activations.filter(a => a.licenseId === license.id)) {
      activation.status = "deleted";
      activation.updatedAt = nowIso();
    }
    saveDb();
  }
  return redirect(res, "/admin/licenses");
}

function activationsPage(req, res, user) {
  const csrf = issueCsrf(req, res);
  const modals = [];
  const cards = db.activations.slice().reverse().map(a => {
    const license = db.licenses.find(l => l.id === a.licenseId);
    const allChecks = db.checks
      .filter(c => c.serverId === a.serverId)
      .slice()
      .reverse();
    const recentChecks = allChecks
      .slice(0, 3)
      .map(c => `<li><span>${fmtDate(c.createdAt)}</span>${badge(c.status)}</li>`)
      .join("") || "<li><span>Brak logow sprawdzen.</span></li>";
    const modalId = `logs-${escapeAttr(a.id)}`;
    if (allChecks.length > 3) {
      modals.push(logsModal(modalId, a, allChecks));
    }
    const moreButton = allChecks.length > 3
      ? `<button class="ghost-button" type="button" data-open-modal="${modalId}">Pokaz wiecej (${allChecks.length})</button>`
      : "";
    const actions = activationActions(csrf, a);
    return `<section class="server-card">
      <div class="server-head">
        <span class="server-icon-wrap"><img class="server-icon" src="${serverIcon(a)}" width="48" height="48" alt=""></span>
        <div>
          <h2>${escapeHtml(a.serverName || a.serverIp || "Serwer Minecraft")}</h2>
          <p><code>${escapeHtml(a.serverId)}</code></p>
        </div>
        ${badge(a.status)}
      </div>
      <div class="server-metrics">
        ${miniMetric("Online", `${num(a.onlinePlayers)}/${num(a.maxPlayers)}`)}
        ${miniMetric("Brushe lacznie", num(a.brushesKnown))}
        ${miniMetric("Brushe live", num(a.brushesLive))}
        ${miniMetric("Incydenty kopii", num(a.copyIncidents))}
      </div>
      <div class="server-details">
        <span>Licencja</span><strong>${license ? `<code>${escapeHtml(license.key)}</code>` : "-"}</strong>
        <span>Paczka</span><strong>${escapeHtml(a.productId)}</strong>
        <span>Adres</span><strong>${escapeHtml(`${a.serverIp || "-"}:${a.serverPort || "-"}`)}</strong>
        <span>Core</span><strong>${escapeHtml(a.pluginVersion || "-")}</strong>
        <span>Paper/Bukkit</span><strong>${escapeHtml(a.bukkitVersion || "-")}</strong>
        <span>Ostatnio</span><strong>${fmtDate(a.updatedAt || a.createdAt)}</strong>
      </div>
      <div class="log-title">Historia sprawdzen licencji</div>
      <ul class="server-log">${recentChecks}</ul>
      ${moreButton}
      <div class="row-actions">${actions}</div>
    </section>`;
  }).join("") || card("Serwery", "<p>Nie ma jeszcze zadnych prob aktywacji.</p>");
  return page(res, 200, "Serwery", `<div class="server-grid">${cards}</div>${modals.join("")}`, user);
}

function logsModal(modalId, activation, checks) {
  const statuses = Array.from(new Set(checks.map(c => String(c.status || "UNKNOWN")))).sort();
  const options = [`<option value="">Wszystkie statusy</option>`]
    .concat(statuses.map(status => `<option value="${escapeAttr(status.toLowerCase())}">${escapeHtml(status)}</option>`))
    .join("");
  const rows = checks.map(c => {
    const text = [
      fmtDate(c.createdAt),
      c.status,
      c.licenseKey,
      c.serverId,
      c.onlinePlayers,
      c.maxPlayers,
      c.brushesKnown,
      c.copyIncidents
    ].join(" ").toLowerCase();
    return `<tr data-status="${escapeAttr(String(c.status || "").toLowerCase())}" data-search="${escapeAttr(text)}">
      <td>${fmtDate(c.createdAt)}</td>
      <td>${badge(c.status)}</td>
      <td><code>${escapeHtml(c.licenseKey || "-")}</code></td>
      <td>${escapeHtml(`${num(c.onlinePlayers)}/${num(c.maxPlayers)}`)}</td>
      <td>${escapeHtml(num(c.brushesKnown))}</td>
      <td>${escapeHtml(num(c.copyIncidents))}</td>
    </tr>`;
  }).join("");
  return `<div class="modal-backdrop" id="${modalId}" hidden>
    <section class="modal-panel" role="dialog" aria-modal="true" aria-label="Logi licencji">
      <div class="modal-head">
        <div>
          <p class="eyebrow">Historia licencji</p>
          <h2>${escapeHtml(activation.serverName || activation.serverIp || "Serwer Minecraft")}</h2>
          <p><code>${escapeHtml(activation.serverId)}</code></p>
        </div>
        <button type="button" class="icon-button" data-close-modal="${modalId}" aria-label="Zamknij">X</button>
      </div>
      <div class="modal-tools">
        <label>Szukaj<input type="search" placeholder="licencja, status, data, server id..." data-log-search="${modalId}"></label>
        <label>Status<select data-log-status="${modalId}">${options}</select></label>
      </div>
      <div class="modal-table">
        <table>
          <thead><tr><th>Czas</th><th>Status</th><th>Licencja</th><th>Online</th><th>Brushe</th><th>Kopie</th></tr></thead>
          <tbody data-log-body="${modalId}">${rows}</tbody>
        </table>
      </div>
    </section>
  </div>`;
}

function activationActions(csrf, activation) {
  if (activation.status === "approved") {
    return [
      formButton(csrf, "/admin/activations", { action: "detach", id: activation.id }, "Odlacz serwer"),
      formButton(csrf, "/admin/activations", { action: "reject", id: activation.id }, "Zablokuj", "danger")
    ].join("");
  }
  if (activation.status === "pending" || activation.status === "conflict") {
    return [
      formButton(csrf, "/admin/activations", { action: "approve", id: activation.id }, "Akceptuj"),
      formButton(csrf, "/admin/activations", { action: "reject", id: activation.id }, "Odrzuc", "danger")
    ].join("");
  }
  return formButton(csrf, "/admin/activations", { action: "approve", id: activation.id }, "Aktywuj ponownie");
}

async function activationsSubmit(req, res) {
  const form = await parseForm(req);
  if (!validCsrf(req, form.csrf)) return forbidden(res);
  const activation = db.activations.find(a => a.id === form.id);
  if (activation) {
    if (form.action === "approve") {
      for (const other of db.activations.filter(a => a.licenseId === activation.licenseId && a.id !== activation.id && a.status === "approved")) {
        other.status = "detached";
        other.updatedAt = nowIso();
      }
      activation.status = "approved";
    }
    if (form.action === "reject") activation.status = "rejected";
    if (form.action === "detach") activation.status = "detached";
    activation.updatedAt = nowIso();
    saveDb();
  }
  return redirect(res, "/admin/activations");
}

function publicKeyPage(req, res, user) {
  return page(res, 200, "Klucz publiczny", card("Klucz publiczny do core", `
    <p>Wklej ten klucz do konfiguracji core, zeby plugin mogl sprawdzac podpis odpowiedzi API.</p>
    <textarea readonly rows="10">${escapeHtml(keys.publicKey)}</textarea>
  `), user);
}

async function apiCheck(req, res) {
  const body = await parseJson(req);
  const productId = normalizeId(body.productId || "mobcash");
  const licenseKeyRaw = String(body.licenseKey || "").trim();
  const serverId = String(body.serverId || "").trim();
  if (!licenseKeyRaw || !serverId) {
    return signedLicense(res, 400, { valid: false, status: "BAD_REQUEST", message: "Brak licenseKey albo serverId." });
  }
  const product = db.products.find(p => p.id === productId);
  const license = db.licenses.find(l => l.key.toUpperCase() === licenseKeyRaw.toUpperCase() && l.productId === productId);
  let activation = license ? db.activations.find(a => a.licenseId === license.id && a.serverId === serverId) : null;
  let status = "INVALID";
  let message = "Licencja nie istnieje.";
  let valid = false;

  if (!product || !product.active) {
    status = "PRODUCT_DISABLED";
    message = "Paczka jest wylaczona.";
  } else if (!license) {
    status = "INVALID";
  } else if (license.status !== "active") {
    status = license.status.toUpperCase();
    message = "Licencja nie jest aktywna.";
  } else if (license.expiresAt && Date.now() > Date.parse(license.expiresAt)) {
    status = "EXPIRED";
    message = "Licencja wygasla.";
  } else {
    if (!activation) {
      const hasApproved = db.activations.some(a => a.licenseId === license.id && a.status === "approved");
      activation = {
        id: id("srv"),
        licenseId: license.id,
        productId,
        serverId,
        serverIp: String(body.serverIp || req.socket.remoteAddress || ""),
        serverPort: Number(body.serverPort || 0),
        serverName: String(body.serverName || ""),
        onlinePlayers: Number(body.onlinePlayers || 0),
        maxPlayers: Number(body.maxPlayers || 0),
        brushesKnown: Number(body.brushesKnown || 0),
        brushesLive: Number(body.brushesLive || 0),
        copyIncidents: Number(body.copyIncidents || 0),
        bukkitVersion: String(body.bukkitVersion || ""),
        pluginVersion: String(body.pluginVersion || ""),
        status: hasApproved ? "conflict" : "pending",
        createdAt: nowIso(),
        updatedAt: nowIso()
      };
      db.activations.push(activation);
    } else {
      activation.serverIp = String(body.serverIp || activation.serverIp || req.socket.remoteAddress || "");
      activation.serverPort = Number(body.serverPort || activation.serverPort || 0);
      activation.serverName = String(body.serverName || activation.serverName || "");
      activation.onlinePlayers = Number(body.onlinePlayers ?? activation.onlinePlayers ?? 0);
      activation.maxPlayers = Number(body.maxPlayers ?? activation.maxPlayers ?? 0);
      activation.brushesKnown = Number(body.brushesKnown ?? activation.brushesKnown ?? 0);
      activation.brushesLive = Number(body.brushesLive ?? activation.brushesLive ?? 0);
      activation.copyIncidents = Number(body.copyIncidents ?? activation.copyIncidents ?? 0);
      activation.bukkitVersion = String(body.bukkitVersion || activation.bukkitVersion || "");
      activation.pluginVersion = String(body.pluginVersion || activation.pluginVersion || "");
      activation.updatedAt = nowIso();
    }
    if (activation.status === "approved") {
      const otherApproved = db.activations.some(a => a.licenseId === license.id && a.id !== activation.id && a.status === "approved");
      if (otherApproved) {
        status = "CONFLICT";
        message = "Licencja ma juz inny zaakceptowany serwer.";
      } else {
        valid = true;
        status = "ACTIVE";
        message = "Licencja aktywna.";
      }
    } else {
      status = activation.status.toUpperCase();
      message = activation.status === "pending" ? "Serwer oczekuje na akceptacje wlasciciela." : "Serwer nie jest zaakceptowany.";
    }
  }

  db.checks.push({
    id: id("chk"),
    productId,
    licenseKey: licenseKeyRaw,
    serverId,
    onlinePlayers: Number(body.onlinePlayers || 0),
    maxPlayers: Number(body.maxPlayers || 0),
    brushesKnown: Number(body.brushesKnown || 0),
    copyIncidents: Number(body.copyIncidents || 0),
    status,
    createdAt: nowIso()
  });
  db.checks = db.checks.slice(-300);
  saveDb();

  return signedLicense(res, 200, {
    valid,
    status,
    message,
    productId,
    serverId,
    checkedAt: nowIso(),
    graceSeconds: LICENSE_GRACE_HOURS * 3600
  });
}

function signedLicense(res, code, payload) {
  const canonical = canonicalJson(payload);
  const signature = crypto.sign("RSA-SHA256", Buffer.from(canonical), keys.privateKey).toString("base64");
  return json(res, code, { payload, signature, algorithm: "RSA-SHA256" });
}

function requireAuth(req, res) {
  const sid = cookies(req).sid;
  const session = sid ? sessions.get(sid) : null;
  if (!session || session.expiresAt < Date.now()) {
    if (sid) sessions.delete(sid);
    saveSessions();
    redirect(res, "/login");
    return null;
  }
  session.expiresAt = Date.now() + SESSION_TTL_MS;
  saveSessions();
  return db.users.find(u => u.id === session.userId) || null;
}

function issueCsrf(req, res) {
  const sid = cookies(req).sid;
  const session = sid ? sessions.get(sid) : null;
  if (session) return session.csrf;
  const token = randomHex(24);
  setCookie(res, "csrf", token, 3600);
  return token;
}

function validCsrf(req, token) {
  const sid = cookies(req).sid;
  const session = sid ? sessions.get(sid) : null;
  return session ? session.csrf === token : cookies(req).csrf === token;
}

function page(res, code, title, body, user = null) {
  const nav = user ? `
    <nav>
      <a href="/admin">Panel</a>
      <a href="/admin/licenses">Licencje</a>
      <a href="/admin/activations">Serwery</a>
      <a href="/admin/products">Paczki</a>
      <a href="/admin/public-key">Klucz</a>
      <form method="post" action="/logout"><button>Wyloguj</button></form>
    </nav>` : "";
  res.writeHead(code, { "content-type": "text/html; charset=utf-8", "x-frame-options": "DENY" });
  res.end(`<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} - Licencje</title>
  <link rel="stylesheet" href="/assets/app.css">
</head>
<body>
  <div class="shell">
    <header><a class="brand" href="/admin"><span></span> License Center</a>${nav}</header>
    <main>${body}</main>
  </div>
  <script>
    document.addEventListener('click', event => {
      const open = event.target.closest('[data-open-modal]');
      if (open) {
        const modal = document.getElementById(open.dataset.openModal);
        if (modal) modal.hidden = false;
      }
      const close = event.target.closest('[data-close-modal]');
      if (close) {
        const modal = document.getElementById(close.dataset.closeModal);
        if (modal) modal.hidden = true;
      }
      if (event.target.classList.contains('modal-backdrop')) {
        event.target.hidden = true;
      }
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') {
        document.querySelectorAll('.modal-backdrop:not([hidden])').forEach(modal => modal.hidden = true);
      }
    });
    function filterLogs(id) {
      const search = (document.querySelector('[data-log-search="' + id + '"]')?.value || '').toLowerCase().trim();
      const status = (document.querySelector('[data-log-status="' + id + '"]')?.value || '').toLowerCase();
      document.querySelectorAll('[data-log-body="' + id + '"] tr').forEach(row => {
        const okSearch = !search || row.dataset.search.includes(search);
        const okStatus = !status || row.dataset.status === status;
        row.hidden = !(okSearch && okStatus);
      });
    }
    document.addEventListener('input', event => {
      const input = event.target.closest('[data-log-search]');
      if (input) filterLogs(input.dataset.logSearch);
    });
    document.addEventListener('change', event => {
      const select = event.target.closest('[data-log-status]');
      if (select) filterLogs(select.dataset.logStatus);
    });
  </script>
</body>
</html>`);
}

function css(res) {
  res.writeHead(200, { "content-type": "text/css; charset=utf-8", "cache-control": "no-store, max-age=0" });
  res.end(`
:root {
  color-scheme: dark;
  --bg: #050813;
  --bg-soft: #0b1220;
  --panel: rgba(12, 20, 36, .86);
  --panel-strong: rgba(16, 29, 52, .94);
  --text: #eef6ff;
  --muted: #95a8c6;
  --line: rgba(119, 158, 213, .22);
  --line-strong: rgba(128, 184, 255, .42);
  --blue: #5fa8ff;
  --blue-strong: #2f7dff;
  --cyan: #38d8ff;
  --accent: #48f0bd;
  --danger: #ff647c;
  --warn: #ffd166;
  --shadow: 0 24px 80px rgba(0, 0, 0, .36);
}
* { box-sizing: border-box; }
html { min-height: 100%; }
body {
  min-height: 100vh;
  margin: 0;
  color: var(--text);
  font: 15px/1.5 Inter, Segoe UI, system-ui, sans-serif;
  background:
    linear-gradient(135deg, rgba(47,125,255,.20), transparent 30%),
    linear-gradient(315deg, rgba(72,240,189,.12), transparent 28%),
    var(--bg);
  overflow-x: hidden;
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background-image:
    linear-gradient(rgba(119,158,213,.08) 1px, transparent 1px),
    linear-gradient(90deg, rgba(119,158,213,.08) 1px, transparent 1px);
  background-size: 44px 44px;
  mask-image: linear-gradient(to bottom, rgba(0,0,0,.95), transparent 82%);
  animation: gridMove 18s linear infinite;
}
a { color: inherit; }
button, .button {
  position: relative;
  border: 1px solid var(--line);
  background: linear-gradient(180deg, rgba(95,168,255,.15), rgba(12,20,36,.76));
  color: var(--text);
  border-radius: 8px;
  padding: 10px 14px;
  text-decoration: none;
  cursor: pointer;
  transition: transform .18s ease, border-color .18s ease, background .18s ease, box-shadow .18s ease;
}
button:hover, .button:hover {
  transform: translateY(-1px);
  border-color: var(--line-strong);
  box-shadow: 0 10px 28px rgba(47,125,255,.18);
}
button:focus-visible, .button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible {
  outline: 2px solid rgba(56,216,255,.72);
  outline-offset: 2px;
}
.primary {
  border: 0;
  color: #03101f;
  font-weight: 900;
  background: linear-gradient(135deg, var(--cyan), var(--blue), var(--accent));
  box-shadow: 0 14px 36px rgba(47,125,255,.28);
}
.danger { border-color: rgba(255,100,124,.42); color: #ffd1d8; }
.shell { position: relative; max-width: 1220px; margin: 0 auto; padding: 24px; }
header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  margin-bottom: 28px;
  animation: fadeDown .45s ease both;
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 950;
  text-decoration: none;
  letter-spacing: .01em;
}
.brand span {
  width: 15px;
  height: 15px;
  border-radius: 5px;
  background: linear-gradient(135deg, var(--cyan), var(--accent));
  box-shadow: 0 0 28px rgba(56,216,255,.85);
  animation: pulseMark 2.8s ease-in-out infinite;
}
nav { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
nav a, nav button {
  font-size: 13px;
  padding: 8px 10px;
  background: rgba(10, 18, 32, .68);
  backdrop-filter: blur(10px);
}
.hero {
  min-height: 300px;
  display: grid;
  grid-template-columns: 1.06fr .94fr;
  gap: 28px;
  align-items: end;
  padding: 46px 0;
  animation: fadeUp .55s ease both;
}
.hero h1 {
  max-width: 760px;
  font-size: clamp(40px, 6vw, 76px);
  line-height: .92;
  margin: 8px 0 18px;
  letter-spacing: 0;
  text-wrap: balance;
}
.hero p { max-width: 700px; color: var(--muted); font-size: 17px; }
.eyebrow {
  text-transform: uppercase;
  letter-spacing: .14em;
  color: var(--accent) !important;
  font-weight: 850;
  font-size: 12px !important;
}
.metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.metric, .card {
  position: relative;
  overflow: hidden;
  background: linear-gradient(180deg, rgba(18,34,62,.88), rgba(8,14,27,.82));
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 18px;
  box-shadow: var(--shadow);
  backdrop-filter: blur(18px);
  animation: fadeUp .55s ease both;
}
.metric::before, .card::before {
  content: "";
  position: absolute;
  inset: 0;
  border-top: 1px solid rgba(255,255,255,.12);
  pointer-events: none;
}
.metric:hover, .card:hover {
  border-color: var(--line-strong);
  transform: translateY(-2px);
  transition: transform .2s ease, border-color .2s ease;
}
.metric strong {
  display: block;
  font-size: 34px;
  line-height: 1;
  color: #ffffff;
}
.metric span, .card p, .card small { color: var(--muted); }
.grid.two { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.card h2 { margin: 0 0 14px; font-size: 22px; letter-spacing: 0; }
.actions { display: flex; gap: 10px; flex-wrap: wrap; }
.form-grid { display: grid; gap: 14px; }
.form-grid.inline { grid-template-columns: repeat(4, minmax(0, 1fr)); align-items: end; margin-bottom: 18px; }
label { display: grid; gap: 6px; color: var(--muted); font-size: 13px; }
input, select, textarea {
  width: 100%;
  border: 1px solid var(--line);
  background: rgba(4, 9, 18, .82);
  color: var(--text);
  border-radius: 8px;
  padding: 11px 12px;
  font: inherit;
  transition: border-color .18s ease, box-shadow .18s ease, background .18s ease;
}
input:focus, select:focus, textarea:focus {
  border-color: rgba(56,216,255,.72);
  background: rgba(5, 12, 24, .96);
  box-shadow: 0 0 0 4px rgba(56,216,255,.10);
}
textarea { font-family: Consolas, monospace; }
.notice {
  display: grid;
  gap: 10px;
  background: linear-gradient(180deg, rgba(11, 24, 45, .92), rgba(7, 14, 27, .92));
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 14px;
}
.notice code, td code {
  font-family: Consolas, monospace;
  color: #b7f7df;
  word-break: break-all;
}
.qr {
  width: 196px;
  height: 196px;
  background: #fff;
  border-radius: 8px;
  padding: 10px;
  border: 1px solid #d7dee9;
  box-shadow: 0 18px 42px rgba(0,0,0,.25);
}
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 11px 8px; vertical-align: top; }
tr { transition: background .16s ease; }
tbody tr:hover { background: rgba(95,168,255,.06); }
th { font-size: 12px; text-transform: uppercase; color: var(--muted); letter-spacing: .08em; }
.badge {
  display: inline-flex;
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 3px 8px;
  font-size: 12px;
  background: rgba(255,255,255,.035);
}
.badge.active, .badge.approved { border-color: rgba(72,240,189,.45); color: #7ff0c7; }
.badge.pending { border-color: rgba(255,209,102,.45); color: #ffe08a; }
.badge.disabled, .badge.deleted, .badge.rejected, .badge.detached, .badge.conflict { border-color: rgba(255,100,124,.45); color: #ff9cac; }
.row-actions { display: flex; gap: 6px; flex-wrap: wrap; }
.row-actions form { display: inline; }
.row-actions button { padding: 7px 9px; font-size: 12px; }
.ghost-button {
  position: relative;
  z-index: 1;
  width: fit-content;
  margin: -2px 0 14px;
  padding: 8px 11px;
  font-size: 12px;
  color: #cfe5ff;
  background: rgba(95,168,255,.10);
}
.server-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 16px;
}
.server-card {
  position: relative;
  overflow: hidden;
  padding: 18px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background:
    linear-gradient(145deg, rgba(30, 55, 98, .82), rgba(7, 14, 28, .92)),
    radial-gradient(circle at 20% 0%, rgba(56,216,255,.18), transparent 34%);
  box-shadow: var(--shadow);
  animation: fadeUp .55s ease both;
  transition: transform .22s ease, border-color .22s ease, box-shadow .22s ease;
}
.server-card::after {
  content: "";
  position: absolute;
  inset: -40% auto auto -30%;
  width: 260px;
  height: 260px;
  background: radial-gradient(circle, rgba(56,216,255,.22), transparent 68%);
  opacity: .65;
  transform: translate3d(0,0,0);
  transition: transform .35s ease, opacity .35s ease;
  pointer-events: none;
}
.server-card:hover {
  transform: translateY(-4px);
  border-color: rgba(56,216,255,.52);
  box-shadow: 0 28px 95px rgba(0,0,0,.44), 0 0 50px rgba(47,125,255,.12);
}
.server-card:hover::after {
  transform: translate3d(36px, 24px, 0);
  opacity: .95;
}
.server-head {
  position: relative;
  display: grid;
  grid-template-columns: 58px minmax(0, 1fr) auto;
  gap: 12px;
  align-items: center;
  z-index: 1;
}
.server-head h2 { margin: 0; font-size: 20px; }
.server-head p { margin: 2px 0 0; color: var(--muted); }
.server-icon-wrap {
  width: 58px;
  height: 58px;
  display: grid;
  place-items: center;
  overflow: hidden;
  border-radius: 8px;
  border: 1px solid rgba(255,255,255,.16);
  background: #08101f;
  box-shadow: 0 14px 34px rgba(0,0,0,.28);
}
.server-icon {
  width: 58px;
  height: 58px;
  max-width: 58px;
  max-height: 58px;
  min-width: 58px;
  min-height: 58px;
  border-radius: 8px;
  object-fit: cover;
  display: block;
  image-rendering: pixelated;
}
.server-metrics {
  position: relative;
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
  margin: 16px 0;
  z-index: 1;
}
.mini-metric {
  min-height: 74px;
  display: grid;
  align-content: center;
  gap: 4px;
  padding: 10px;
  border: 1px solid rgba(119,158,213,.18);
  border-radius: 8px;
  background: rgba(5, 12, 24, .46);
}
.mini-metric strong { font-size: 22px; line-height: 1; color: #fff; }
.mini-metric span { color: var(--muted); font-size: 12px; }
.server-details {
  position: relative;
  display: grid;
  grid-template-columns: 110px 1fr;
  gap: 8px 12px;
  padding: 12px;
  border: 1px solid rgba(119,158,213,.16);
  border-radius: 8px;
  background: rgba(3, 8, 17, .38);
  z-index: 1;
}
.server-details span { color: var(--muted); }
.server-details strong { min-width: 0; overflow-wrap: anywhere; }
.server-log {
  position: relative;
  list-style: none;
  display: grid;
  gap: 6px;
  padding: 0;
  margin: 14px 0;
  z-index: 1;
}
.log-title {
  position: relative;
  margin-top: 14px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: .08em;
  text-transform: uppercase;
  z-index: 1;
}
.server-log li {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 8px 10px;
  border-radius: 8px;
  border: 1px solid rgba(119,158,213,.12);
  background: rgba(255,255,255,.028);
}
.server-log span { color: var(--muted); font-size: 12px; }
.modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 50;
  display: grid;
  place-items: center;
  padding: 24px;
  background: rgba(2, 6, 14, .72);
  backdrop-filter: blur(12px);
  animation: fadeIn .16s ease both;
}
.modal-backdrop[hidden] { display: none; }
.modal-panel {
  width: min(980px, 100%);
  max-height: min(760px, calc(100vh - 48px));
  overflow: hidden;
  display: grid;
  grid-template-rows: auto auto 1fr;
  border: 1px solid var(--line-strong);
  border-radius: 8px;
  background: linear-gradient(180deg, rgba(18,34,62,.98), rgba(7,14,28,.98));
  box-shadow: 0 32px 120px rgba(0,0,0,.62), 0 0 80px rgba(47,125,255,.16);
  animation: modalPop .18s ease both;
}
.modal-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
  padding: 18px;
  border-bottom: 1px solid var(--line);
}
.modal-head h2 { margin: 2px 0 4px; font-size: 26px; }
.modal-head p { margin: 0; color: var(--muted); }
.icon-button {
  width: 38px;
  height: 38px;
  padding: 0;
  display: grid;
  place-items: center;
  font-weight: 900;
}
.modal-tools {
  display: grid;
  grid-template-columns: 1fr 220px;
  gap: 12px;
  padding: 14px 18px;
  border-bottom: 1px solid var(--line);
  background: rgba(255,255,255,.025);
}
.modal-table {
  overflow: auto;
  padding: 0 18px 18px;
}
.modal-table table { min-width: 760px; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
@keyframes modalPop { from { opacity: 0; transform: translateY(12px) scale(.985); } to { opacity: 1; transform: translateY(0) scale(1); } }
@keyframes fadeUp { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: translateY(0); } }
@keyframes fadeDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
@keyframes pulseMark { 0%,100% { transform: scale(1); filter: brightness(1); } 50% { transform: scale(1.12); filter: brightness(1.22); } }
@keyframes gridMove { from { background-position: 0 0, 0 0; } to { background-position: 44px 44px, 44px 44px; } }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; }
}
@media(max-width:800px) {
  .hero, .grid.two, .form-grid.inline { grid-template-columns: 1fr; }
  .metrics { grid-template-columns: 1fr; }
  .server-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .server-head { grid-template-columns: 52px 1fr; }
  .server-head .badge { grid-column: 1 / -1; justify-self: start; }
  .modal-tools { grid-template-columns: 1fr; }
  header { align-items: flex-start; flex-direction: column; }
}
`);
}

function card(title, content) {
  return `<section class="card"><h2>${escapeHtml(title)}</h2>${content}</section>`;
}

function metric(label, value) {
  return `<div class="metric"><strong>${escapeHtml(String(value))}</strong><span>${escapeHtml(label)}</span></div>`;
}

function miniMetric(label, value) {
  return `<div class="mini-metric"><strong>${escapeHtml(String(value))}</strong><span>${escapeHtml(label)}</span></div>`;
}

function serverIcon(activation) {
  const host = String(activation.serverIp || "").replace(/^::ffff:/, "").trim();
  if (!host || host === "127.0.0.1" || host === "::1" || host.toLowerCase() === "localhost") {
    return "data:image/svg+xml;base64," + Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#38d8ff"/><stop offset="1" stop-color="#48f0bd"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="#0b1628"/><path d="M16 42V22l16-9 16 9v20l-16 9-16-9Z" fill="url(#g)" opacity=".92"/><path d="M24 28h16v16H24z" fill="#06101e" opacity=".8"/></svg>`).toString("base64");
  }
  return `https://api.mcsrvstat.us/icon/${encodeURIComponent(host)}`;
}

function num(value) {
  return Number.isFinite(Number(value)) ? String(Number(value)) : "0";
}

function table(headers, rows) {
  if (!rows.length) return "<p>Brak danych.</p>";
  return `<table><thead><tr>${headers.map(h => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead><tbody>${rows.map(row => `<tr>${row.map(cell => `<td>${cell}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

function formButton(csrf, action, fields, label, cls = "") {
  return `<form method="post" action="${action}">${hidden("csrf", csrf)}${Object.entries(fields).map(([k, v]) => hidden(k, v)).join("")}<button class="${cls}">${escapeHtml(label)}</button></form>`;
}

function badge(status) {
  const safe = String(status || "").toLowerCase();
  return `<span class="badge ${safe}">${escapeHtml(status || "-")}</span>`;
}

function hidden(name, value) {
  return `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(String(value ?? ""))}">`;
}

function productName(idValue) {
  return db.products.find(p => p.id === idValue)?.name || idValue;
}

function redirect(res, location) {
  res.writeHead(302, { location });
  res.end();
}

function forbidden(res) {
  return page(res, 403, "Brak dostepu", card("Brak dostepu", "<p>Sesja wygasla albo token formularza jest niepoprawny.</p>"));
}

function json(res, code, data) {
  res.writeHead(code, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(data));
}

async function parseForm(req) {
  const raw = await rawBody(req, 1024 * 1024);
  const params = new URLSearchParams(raw);
  return Object.fromEntries(params.entries());
}

async function parseJson(req) {
  const raw = await rawBody(req, 1024 * 1024);
  return raw ? JSON.parse(raw) : {};
}

function rawBody(req, max) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", chunk => {
      data += chunk;
      if (data.length > max) {
        reject(new Error("Za duze zapytanie."));
        req.destroy();
      }
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, key) => err ? reject(err) : resolve(key));
  });
  return `scrypt$${salt.toString("base64")}$${hash.toString("base64")}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const salt = Buffer.from(parts[1], "base64");
  const expected = Buffer.from(parts[2], "base64");
  const actual = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, key) => err ? reject(err) : resolve(key));
  });
  return crypto.timingSafeEqual(expected, actual);
}

function verifyTotp(secret, code) {
  const clean = String(code || "").replace(/\D/g, "");
  if (clean.length !== 6) return false;
  const key = base32Decode(secret);
  const step = Math.floor(Date.now() / 30000);
  for (let offset = -1; offset <= 1; offset++) {
    if (totpCode(key, step + offset) === clean) return true;
  }
  return false;
}

function totpCode(key, counter) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const binary = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(binary % 1000000).padStart(6, "0");
}

function base32Random() {
  return base32Encode(crypto.randomBytes(20));
}

function base32Encode(buffer) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of String(input || "").replace(/=+$/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) continue;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function otpauth(label, secret) {
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent("MobCash Licencje")}&algorithm=SHA1&digits=6&period=30`;
}

function cookies(req) {
  return Object.fromEntries(String(req.headers.cookie || "").split(";").map(part => part.trim()).filter(Boolean).map(part => {
    const index = part.indexOf("=");
    return [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
  }));
}

function setCookie(res, name, value, maxAge) {
  const cookie = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(maxAge)}${COOKIE_SECURE ? "; Secure" : ""}`;
  const current = res.getHeader("set-cookie");
  res.setHeader("set-cookie", current ? [].concat(current, cookie) : cookie);
}

function id(prefix) {
  return `${prefix}_${randomHex(12)}`;
}

function licenseKey(productId) {
  return `${productId.toUpperCase().slice(0, 3)}-${randomHex(4).toUpperCase()}-${randomHex(4).toUpperCase()}-${randomHex(4).toUpperCase()}`;
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString("hex");
}

function normalizeId(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9_-]/g, "").slice(0, 48);
}

function nowIso() {
  return new Date().toISOString();
}

function fmtDate(value) {
  if (!value) return "";
  return new Date(value).toLocaleString("pl-PL");
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  }[char]));
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/`/g, "&#96;");
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
