# Piper's Sandbox

Meta Ads simulator. Pages live in `public/`; every page is locked behind a personal access code by `netlify/edge-functions/access-gate.js`. Buyers get their code by email after paying, via `netlify/functions/stripe-webhook.mjs`.

## One-time setup on Netlify

The access check runs on Netlify's servers, which drag-and-drop deploys can't do, so the site must deploy from this GitHub repo.

1. In Netlify, open the site, then **Site configuration > Build & deploy > Link repository**, and pick `pipersandbox-lab/pipers-sandbox`. Leave the build command empty. The publish directory comes from `netlify.toml`.
2. In **Site configuration > Environment variables**, add:
   - `ACCESS_SECRET`: a long random string, such as 40 random letters and numbers. Keep it private. Changing it switches off every existing code.
   - `ADMIN_PASSWORD`: the password for the code generator page.
   - `MAX_DEVICES` (optional): how many browsers each code works in. Defaults to 2.
   - `REVOKED_CODES` (optional): names or full codes to switch off, separated by commas, such as `MARIA, JO-0-6AAB8B7261B7`.
3. Go to **Deploys > Trigger deploy**. After changing an environment variable, deploy again so the change takes effect.

## Buyers claim access with their purchase email

Buyers go to `https://<your-site>/claim` and type the email they paid with. The site checks Stripe for a successful, unrefunded payment from that email and signs them in. The same email always gets the same code, so the two-browser limit still applies.

1. In Stripe, go to **Developers > API keys > Create restricted key**. Give it **Charges: Read** and **Customers: Read** only, and copy the key (`rk_live_...`).
2. Add it in Netlify as `STRIPE_SECRET_KEY`, then redeploy. `PRODUCT_MATCH` and `ACCESS_DAYS` (below) also apply here.
3. In Stan Store, add the claim link to the product's purchase confirmation.

## Optional: email codes automatically (Stripe webhook + Resend)

1. Sign up at resend.com, add and verify your domain, and create an API key.
2. In Stripe (live mode), go to **Developers > Webhooks** and add an endpoint: `https://<your-site>/stripe-webhook`, event `charge.succeeded`. Copy its signing secret (`whsec_...`).
3. Add these Netlify environment variables, then redeploy:
   - `STRIPE_WEBHOOK_SECRET`: the `whsec_...` signing secret.
   - `RESEND_API_KEY`: the Resend API key.
   - `EMAIL_FROM`: the sender, such as `Piper's Sandbox <access@yourdomain.com>` (must use your verified domain).
   - `PRODUCT_MATCH` (optional): text found in the simulator payment's description in Stripe, so other products don't get codes.
   - `ACCESS_DAYS` (optional): how many days a code works. Leave it out for lifetime access.
4. Make a real purchase, then refund it. Netlify's function logs (**Logs > Functions > stripe-webhook**) show each payment's description and whether an email was sent.

## Giving someone access by hand

1. Go to `https://<your-site>/admin`, enter the admin password, the customer's name, and an optional expiry date.
2. Send them the link it gives you, such as `https://<your-site>/?code=MARIA-20271231-XXXXXXXXXXXX`. Opening the link signs them in on that browser. They can also type the code on the lock screen.

Each code works in 2 browsers (or `MAX_DEVICES`). A buyer on a new phone or computer, or who cleared their browser data, needs their devices reset: go to `/admin`, enter their full code under **Reset devices**.

If a code gets shared, add the customer's name to `REVOKED_CODES` and redeploy. Then give them a new code with a different name, such as `MARIA2`.
