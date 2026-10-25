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
//   MAX_DEVICES     how many browsers one code can be used in (optional, default 2)
//   STRIPE_SECRET_KEY  Stripe restricted key with Charges: Read and Customers: Read, used by /claim
//   PRODUCT_MATCH   only payments whose description contains this text count at /claim (optional)
//   ACCESS_DAYS     days of access from the purchase date for /claim (optional; blank = never expires)
//
// /claim lets a buyer type the email they paid with. If Stripe has a successful,
// unrefunded payment for that email, they get a code tied to that email and are
// signed in, subject to the same device limit.
//
// Each browser gets its own random device cookie. The first MAX_DEVICES browsers
// to use a code are remembered in Netlify Blobs; any other browser is refused
// until the device list for that code is reset at /admin.

import { getStore } from "@netlify/blobs";
import { checkCode, makeCode, safeEqual } from "../lib/codes.js";

export { checkCode, makeCode };

const COOKIE = "ps_access";
const DEVICE_COOKIE = "ps_device";

let deviceStore = () => getStore({ name: "devices", consistency: "strong" });
export const setDeviceStoreForTests = (store) => {
  deviceStore = () => store;
};

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

function deviceCookie(id) {
  return `${DEVICE_COOKIE}=${id}; Path=/; Max-Age=${60 * 60 * 24 * 400}; HttpOnly; Secure; SameSite=Lax`;
}

const maxDevices = () => Math.max(1, Number(env("MAX_DEVICES")) || 2);

// Records this browser against the code. Returns false when the code is
// already in use on MAX_DEVICES other browsers.
async function claimDevice(code, deviceId) {
  try {
    const store = deviceStore();
    const entry = (await store.get(code, { type: "json" })) ?? { devices: [] };
    if (entry.devices.some((d) => d.id === deviceId)) return true;
    if (entry.devices.length >= maxDevices()) return false;
    entry.devices.push({ id: deviceId, added: new Date().toISOString() });
    await store.setJSON(code, entry);
    return true;
  } catch (err) {
    // Never lock out a paying customer because storage is briefly unavailable.
    console.error("access-gate: device check failed", err);
    return true;
  }
}

// Checks the code and this browser's device slot, then signs the browser in.
async function unlock(request, secret, revoked, raw, next) {
  const result = await checkCode(secret, revoked, raw);
  if (!result.ok) return lockedPage(result.reason, next);
  const deviceId = readCookie(request, DEVICE_COOKIE) || crypto.randomUUID();
  if (!(await claimDevice(result.code, deviceId))) return lockedPage("devices", next);
  const headers = new Headers({ location: next, "cache-control": "no-store" });
  headers.append("set-cookie", accessCookie(result.code, result.expiry));
  headers.append("set-cookie", deviceCookie(deviceId));
  return new Response(null, { status: 303, headers });
}

// Newest successful, unrefunded payment for this email, or null. The buyer's
// email can be on the charge itself or only on its Stripe customer, so customers
// are expanded when the key is allowed to read them.
async function findPurchase(stripeKey, email) {
  const match = env("PRODUCT_MATCH").toLowerCase();
  let expand = "&expand[]=data.customer";
  let after = "";
  for (let page = 0; page < 20; page++) {
    const url = `https://api.stripe.com/v1/charges?limit=100${expand}${after}`;
    const res = await fetch(url, { headers: { authorization: `Bearer ${stripeKey}` } });
    if (res.status === 403 && expand) {
      console.error("access-gate: key can't read customers; matching charge emails only");
      expand = "";
      page--;
      continue;
    }
    if (!res.ok) throw new Error(`Stripe charges list failed: ${res.status}`);
    const { data, has_more } = await res.json();
    for (const c of data) {
      const emails = [c.billing_details?.email, c.receipt_email, c.customer?.email]
        .filter((e) => typeof e === "string")
        .map((e) => e.trim().toLowerCase());
      const text = [c.description, ...Object.values(c.metadata ?? {})].filter(Boolean).join(" ").toLowerCase();
      if (c.status === "succeeded" && !c.refunded && emails.includes(email) && (!match || text.includes(match))) return c;
    }
    if (!has_more || data.length === 0) return null;
    after = `&starting_after=${data[data.length - 1].id}`;
  }
  return null;
}

// Same email always gives the same code, so a buyer can claim again on their second device.
async function codeForEmail(secret, email, charge) {
  const letters = email.split("@")[0].toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12) || "BUYER";
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(email)));
  const suffix = [...hash.slice(0, 2)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  let expiry = "";
  const days = Number(env("ACCESS_DAYS"));
  if (days > 0) expiry = new Date((charge.created + days * 86400) * 1000).toISOString().slice(0, 10);
  return makeCode(secret, letters + suffix, expiry);
}

const CLAIM_MESSAGES = {
  notfound: "We couldn't find a purchase for that email. Use the same email you entered at checkout, or contact help@piperssandbox.com.",
  error: "We couldn't check your purchase right now. Please try again in a minute.",
  setup: "Purchase checking isn't set up yet. Please contact help@piperssandbox.com.",
};

function claimPage(reason, email = "") {
  const error = reason ? `<div class="error">${CLAIM_MESSAGES[reason]}</div>` : "";
  return page(
    "Piper's Sandbox - Get access",
    `<h1>Get your access</h1>
<p>Enter the email you used when you bought Piper's Sandbox.</p>
${error}
<form method="POST" action="/claim">
<label for="email">Purchase email</label>
<input id="email" name="email" type="email" autocomplete="email" value="${escapeHtml(email)}" required />
<button type="submit">Open the simulator</button>
</form>`,
    reason ? 403 : 200,
  );
}

async function claim(request, secret, revoked) {
  if (request.method !== "POST") return claimPage(null);
  const form = await request.formData();
  const email = String(form.get("email") ?? "").trim().toLowerCase();
  const stripeKey = env("STRIPE_SECRET_KEY");
  if (!stripeKey) return claimPage("setup", email);
  let charge;
  try {
    charge = await findPurchase(stripeKey, email);
  } catch (err) {
    console.error("access-gate: purchase lookup failed", err);
    return claimPage("error", email);
  }
  if (!charge) {
    console.log("access-gate: no matching purchase for a claim");
    return claimPage("notfound", email);
  }
  return unlock(request, secret, revoked, await codeForEmail(secret, email, charge), "/");
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
  devices: "This access code is already in use on the maximum number of browsers. Contact Piper's Sandbox if you need to switch devices.",
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
</form>
<p style="margin:20px 0 0;text-align:center">Bought it? <a href="/claim" style="color:#2F2F2F;font-weight:700;text-decoration:underline">Get access with your purchase email</a></p>`,
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
    const resetCode = String(form.get("reset") ?? "").trim().toUpperCase();
    if (!safeEqual(String(form.get("password") ?? ""), adminPassword)) {
      error = "Wrong admin password.";
    } else if (resetCode) {
      await deviceStore().delete(resetCode);
      result = `<div class="result"><p>Devices reset for <code>${escapeHtml(resetCode)}</code>. The next ${maxDevices()} browsers to use it will be allowed.</p></div>`;
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
${result}
<h1 style="margin-top:32px">Reset devices</h1>
<p>Each code works in ${maxDevices()} browsers. If a customer gets a new phone or computer, reset their code here.</p>
<form method="POST" action="/admin">
<label for="reset-password">Admin password</label>
<input id="reset-password" name="password" type="password" required />
<label for="reset">Their full access code</label>
<input id="reset" name="reset" placeholder="MARIA2215-0-XXXXXXXXXXXX" required />
<button type="submit">Reset devices</button>
</form>`,
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
  if (url.pathname === "/claim") return claim(request, secret, revoked);

  if (url.pathname === "/unlock" && request.method === "POST") {
    const form = await request.formData();
    return unlock(request, secret, revoked, form.get("code"), safeNext(form.get("next")));
  }

  // A shared link like /?code=... signs the buyer in, then drops the code from the address bar.
  const fromQuery = url.searchParams.get("code");
  if (fromQuery) {
    url.searchParams.delete("code");
    return unlock(request, secret, revoked, fromQuery, url.pathname + url.search);
  }

  const cookie = readCookie(request, COOKIE);
  if (cookie) {
    const result = await checkCode(secret, revoked, cookie);
    const deviceId = readCookie(request, DEVICE_COOKIE);
    if (result.ok && !(deviceId && (await claimDevice(result.code, deviceId)))) {
      return lockedPage("devices", url.pathname + url.search);
    }
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
