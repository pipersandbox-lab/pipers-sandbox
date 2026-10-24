// Gates the whole site behind personal access codes.
//
// A code looks like MARIA-20271231-1a2b3c4d5e6f:
//   name     who the code belongs to (letters/digits)
//   expiry   last valid day as YYYYMMDD, or 0 for never
//   sig      first 12 hex chars of HMAC-SHA256(ACCESS_SECRET, "NAME|EXPIRY")
// Codes are checked on every request, so revoking one takes effect on the next
// deploy. Codes are made at /admin, or emailed to buyers by
// netlify/functions/stripe-webhook.mjs after a purchase.
//
// Environment variables (Netlify > Site configuration > Environment variables):
//   ACCESS_SECRET   long random string used to sign codes (required)
//   ADMIN_PASSWORD  password for the /admin code generator (required for /admin)
//   REVOKED_CODES   comma-separated names or full codes to block (optional)

import { checkCode, makeCode, safeEqual } from "../lib/codes.js";

export { checkCode, makeCode };

const COOKIE = "ps_access";

const env = (key) => (globalThis.Netlify?.env.get(key) ?? "").trim();

function readCookie(request, name) {
  const header = request.headers.get("cookie") ?? "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return null;
}

function accessCookie(code, expiry) {
  let maxAge = 60 * 60 * 24 * 180;
  if (expiry !== "0") {
    const end = Date.UTC(+expiry.slice(0, 4), +expiry.slice(4, 6) - 1, +expiry.slice(6, 8) + 1);
    maxAge = Math.max(60, Math.floor((end - Date.now()) / 1000));
  }
  return `${COOKIE}=${encodeURIComponent(code)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function page(title, body, status = 200, headers = {}) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="robots" content="noindex" />
<title>${escapeHtml(title)}</title>
<style>
:root{--cream:#F7F0E3;--sage:#A3B18A;--sage2:#DDE5D2;--charcoal:#2F2F2F;--pink:#F4B6C2;--line:#D9D3C7}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--cream);color:var(--charcoal);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border:3px solid var(--sage2);border-radius:24px;padding:32px 28px;width:100%;max-width:420px}
h1{font-size:24px;margin-bottom:8px}p{line-height:1.5;margin-bottom:16px;color:#4a4a4a}
label{display:block;font-weight:700;font-size:13px;margin:12px 0 6px}
input{width:100%;padding:12px 14px;border:2px solid var(--line);border-radius:12px;font-size:16px;font-family:inherit}
input:focus{outline:none;border-color:var(--sage)}
button{margin-top:16px;width:100%;padding:12px;border:none;border-radius:999px;background:var(--sage);color:#fff;font-weight:800;font-size:16px;cursor:pointer;font-family:inherit}
.error{background:#fdecef;border:2px solid var(--pink);border-radius:12px;padding:10px 12px;margin-bottom:12px;font-weight:600}
.result{background:var(--sage2);border-radius:12px;padding:12px;margin-top:16px;word-break:break-all}
.result code{font-size:15px;font-weight:700}
</style>
</head>
<body><main class="card">${body}</main></body>
</html>`;
  return new Response(html, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}

const LOCK_MESSAGES = {
  invalid: "That access code isn't valid. Check it and try again.",
  revoked: "This access code has been switched off. Contact Piper's Sandbox for help.",
  expired: "This access code has expired. Contact Piper's Sandbox to renew your access.",
};

function lockedPage(reason, next) {
  const error = reason ? `<div class="error">${LOCK_MESSAGES[reason]}</div>` : "";
  return page(
    "Piper's Sandbox - Access",
    `<h1>Piper's Sandbox</h1>
<p>Enter the personal access code from your purchase email.</p>
${error}
<form method="POST" action="/unlock">
<input type="hidden" name="next" value="${escapeHtml(next)}" />
<label for="code">Access code</label>
<input id="code" name="code" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="NAME-20271231-XXXXXXXXXXXX" required />
<button type="submit">Unlock</button>
</form>`,
    reason ? 403 : 401,
  );
}

// Only allow redirects back to a path on this site.
const safeNext = (next) => (typeof next === "string" && /^\/(?!\/)/.test(next) ? next : "/");

async function adminPage(request, secret) {
  const adminPassword = env("ADMIN_PASSWORD");
  if (!adminPassword) {
    return page("Admin", "<h1>Admin is off</h1><p>Set the ADMIN_PASSWORD environment variable in Netlify to use this page.</p>", 503);
  }

  let error = "";
  let result = "";
  let name = "";
  let expiry = "";
  if (request.method === "POST") {
    const form = await request.formData();
    name = String(form.get("name") ?? "");
    expiry = String(form.get("expiry") ?? "");
    if (!safeEqual(String(form.get("password") ?? ""), adminPassword)) {
      error = "Wrong admin password.";
    } else {
      const code = await makeCode(secret, name, expiry);
      if (!code) {
        error = "Enter a name using letters or numbers.";
      } else {
        const link = `${new URL(request.url).origin}/?code=${code}`;
        result = `<div class="result"><p><strong>Code:</strong> <code>${code}</code></p><p><strong>Link to send:</strong> <code>${escapeHtml(link)}</code></p></div>`;
      }
    }
  }

  return page(
    "Admin - Access codes",
    `<h1>Make an access code</h1>
<p>Create one code per customer. You can switch a code off later by adding its name or code to REVOKED_CODES in Netlify.</p>
${error ? `<div class="error">${error}</div>` : ""}
<form method="POST" action="/admin">
<label for="password">Admin password</label>
<input id="password" name="password" type="password" required />
<label for="name">Customer name (letters and numbers, must be unique)</label>
<input id="name" name="name" value="${escapeHtml(name)}" placeholder="MARIA" required />
<label for="expiry">Expires after (leave empty for never)</label>
<input id="expiry" name="expiry" type="date" value="${escapeHtml(expiry)}" />
<button type="submit">Make code</button>
</form>
${result}`,
    error ? 400 : 200,
  );
}

export default async (request, context) => {
  const url = new URL(request.url);
  const secret = env("ACCESS_SECRET");
  if (!secret) {
    return page("Not set up", "<h1>Almost ready</h1><p>Set the ACCESS_SECRET environment variable in Netlify, then redeploy.</p>", 503);
  }
  const revoked = env("REVOKED_CODES")
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);

  if (url.pathname === "/admin") return adminPage(request, secret);

  if (url.pathname === "/unlock" && request.method === "POST") {
    const form = await request.formData();
    const next = safeNext(form.get("next"));
    const result = await checkCode(secret, revoked, form.get("code"));
    if (!result.ok) return lockedPage(result.reason, next);
    return new Response(null, {
      status: 303,
      headers: { location: next, "set-cookie": accessCookie(result.code, result.expiry), "cache-control": "no-store" },
    });
  }

  // A shared link like /?code=... signs the buyer in, then drops the code from the address bar.
  const fromQuery = url.searchParams.get("code");
  if (fromQuery) {
    url.searchParams.delete("code");
    const next = url.pathname + url.search;
    const result = await checkCode(secret, revoked, fromQuery);
    if (!result.ok) return lockedPage(result.reason, next);
    return new Response(null, {
      status: 303,
      headers: { location: next, "set-cookie": accessCookie(result.code, result.expiry), "cache-control": "no-store" },
    });
  }

  const cookie = readCookie(request, COOKIE);
  if (cookie) {
    const result = await checkCode(secret, revoked, cookie);
    if (result.ok) {
      const response = await context.next();
      response.headers.set("cache-control", "private, no-store");
      return response;
    }
    return lockedPage(result.reason, url.pathname + url.search);
  }

  return lockedPage(null, url.pathname + url.search);
};

export const config = { path: "/*", excludedPath: ["/stripe-webhook"] };
