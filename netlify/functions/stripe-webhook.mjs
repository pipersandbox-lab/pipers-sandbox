// Emails a personal access link to each buyer after a Stripe payment.
//
// Stripe sends a charge.succeeded event here for every payment (including Stan
// Store sales, which run through Stripe). We check the event really came from
// Stripe, make an access code for the buyer, and email it with Resend.
//
// Environment variables (Netlify > Site configuration > Environment variables):
//   ACCESS_SECRET          same secret the site gate uses (required)
//   STRIPE_WEBHOOK_SECRET  signing secret from the Stripe webhook, whsec_... (required)
//   RESEND_API_KEY         API key from resend.com (required)
//   EMAIL_FROM             sender, e.g. "Piper's Sandbox <access@yourdomain.com>" (required)
//   PRODUCT_MATCH          only send codes when the payment's description contains
//                          this text, e.g. "Simulator" (optional; blank = every payment)
//   ACCESS_DAYS            how many days a code works (optional; blank = never expires)

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { makeCode } from "../lib/codes.js";

const TOLERANCE_SECONDS = 300;

const env = (key) => (process.env[key] ?? "").trim();

// Same check as Stripe's own libraries: HMAC-SHA256 of "timestamp.body".
export function verifyStripeSignature(body, header, secret, now = Date.now()) {
  const parts = Object.fromEntries(
    (header ?? "").split(",").map((p) => p.split("=")).filter((p) => p.length === 2),
  );
  const timestamp = Number(parts.t);
  const signatures = (header ?? "")
    .split(",")
    .filter((p) => p.startsWith("v1="))
    .map((p) => p.slice(3));
  if (!timestamp || signatures.length === 0) return false;
  if (Math.abs(now / 1000 - timestamp) > TOLERANCE_SECONDS) return false;
  const expected = createHmac("sha256", secret).update(`${timestamp}.${body}`).digest();
  return signatures.some((sig) => {
    const given = Buffer.from(sig, "hex");
    return given.length === expected.length && timingSafeEqual(given, expected);
  });
}

// Buyer's first name plus 4 characters derived from the charge, so each buyer
// gets their own revocable name and a retried event produces the same code.
function codeName(charge, email) {
  const first = (charge.billing_details?.name || email.split("@")[0]).split(/\s+/)[0];
  const letters = first.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12) || "BUYER";
  const suffix = createHash("sha256").update(charge.id).digest("hex").slice(0, 4).toUpperCase();
  return letters + suffix;
}

function expiryDate(days) {
  if (!days) return "";
  const end = new Date(Date.now() + Number(days) * 86400000);
  return end.toISOString().slice(0, 10);
}

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function emailHtml(link, code, expiry) {
  const until = expiry ? `<p>Your access works until ${escapeHtml(expiry)}.</p>` : "";
  return `<div style="font-family:Arial,sans-serif;font-size:16px;color:#2F2F2F;max-width:520px">
<h2>Welcome to Piper's Sandbox!</h2>
<p>Thanks for your purchase. Click the button below to open the Meta Ads simulator. It will stay unlocked in that browser.</p>
<p><a href="${escapeHtml(link)}" style="display:inline-block;background:#A3B18A;color:#fff;padding:12px 24px;border-radius:999px;text-decoration:none;font-weight:bold">Open the simulator</a></p>
<p>On another device, go to the site and enter this code:<br><strong>${escapeHtml(code)}</strong></p>
${until}
<p>This link is personal to you, so please don't share it.</p>
</div>`;
}

export default async (request) => {
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });

  const webhookSecret = env("STRIPE_WEBHOOK_SECRET");
  const accessSecret = env("ACCESS_SECRET");
  const resendKey = env("RESEND_API_KEY");
  const from = env("EMAIL_FROM");
  if (!webhookSecret || !accessSecret || !resendKey || !from) {
    console.error("stripe-webhook: missing environment variables");
    return new Response("Not configured", { status: 500 });
  }

  const body = await request.text();
  if (!verifyStripeSignature(body, request.headers.get("stripe-signature"), webhookSecret)) {
    return new Response("Bad signature", { status: 400 });
  }

  const event = JSON.parse(body);
  if (event.type !== "charge.succeeded") return new Response("Ignored", { status: 200 });

  const charge = event.data.object;
  const description = [charge.description, ...Object.values(charge.metadata ?? {})].filter(Boolean).join(" | ");
  console.log(`stripe-webhook: charge ${charge.id} for ${charge.amount} ${charge.currency}, description: ${description || "(none)"}`);

  const match = env("PRODUCT_MATCH").toLowerCase();
  if (match && !description.toLowerCase().includes(match)) {
    console.log("stripe-webhook: not a simulator purchase, skipped");
    return new Response("Skipped", { status: 200 });
  }

  const email = charge.billing_details?.email || charge.receipt_email;
  if (!email) {
    console.error(`stripe-webhook: charge ${charge.id} has no email; make a code at /admin by hand`);
    return new Response("No email", { status: 200 });
  }

  const expiry = expiryDate(env("ACCESS_DAYS"));
  const code = await makeCode(accessSecret, codeName(charge, email), expiry);
  const site = env("URL") || new URL(request.url).origin;
  const link = `${site}/?code=${code}`;

  const sent = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${resendKey}`,
      "content-type": "application/json",
      // Stripe may deliver the same event twice; this stops a second email.
      "idempotency-key": `charge-${charge.id}`,
    },
    body: JSON.stringify({
      from,
      to: [email],
      subject: "Your Piper's Sandbox access link",
      html: emailHtml(link, code, expiry),
    }),
  });
  if (!sent.ok) {
    // A non-2xx reply makes Stripe retry the event later.
    console.error(`stripe-webhook: email failed (${sent.status}): ${await sent.text()}`);
    return new Response("Email failed", { status: 502 });
  }

  console.log(`stripe-webhook: sent code ${code} to ${email}`);
  return new Response("Sent", { status: 200 });
};

export const config = { path: "/stripe-webhook" };
