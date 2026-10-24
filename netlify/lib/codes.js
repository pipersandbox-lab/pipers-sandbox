// Access-code signing and checking, shared by the site gate and the Stripe webhook.
// See netlify/edge-functions/access-gate.js for the code format.

const SIG_LENGTH = 12;

const encoder = new TextEncoder();

async function sign(secret, payload) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(payload)));
  return [...mac].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, SIG_LENGTH);
}

export function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export const cleanName = (name) => name.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 24);

function todayStamp() {
  return Number(new Date().toISOString().slice(0, 10).replace(/-/g, ""));
}

export async function makeCode(secret, name, expiry) {
  const n = cleanName(name);
  const e = expiry ? String(expiry).replace(/-/g, "") : "0";
  if (!n || !/^(0|\d{8})$/.test(e)) return null;
  return `${n}-${e}-${(await sign(secret, `${n}|${e}`)).toUpperCase()}`;
}

// Returns { ok: true, name } or { ok: false, reason }.
export async function checkCode(secret, revoked, raw) {
  const code = (raw ?? "").trim().toUpperCase();
  const match = /^([A-Z0-9]{1,24})-(0|\d{8})-([0-9A-F]{12})$/.exec(code);
  if (!match) return { ok: false, reason: "invalid" };
  const [, name, expiry, sig] = match;
  const expected = (await sign(secret, `${name}|${expiry}`)).toUpperCase();
  if (!safeEqual(sig, expected)) return { ok: false, reason: "invalid" };
  if (revoked.includes(name) || revoked.includes(code)) return { ok: false, reason: "revoked" };
  if (expiry !== "0" && Number(expiry) < todayStamp()) return { ok: false, reason: "expired" };
  return { ok: true, name, code, expiry };
}
