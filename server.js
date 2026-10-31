require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Stripe = require("stripe");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, "data", "events.json");

if (!process.env.STRIPE_SECRET_KEY || !process.env.STRIPE_SECRET_KEY.startsWith("sk_test_")) {
  console.error("Missing STRIPE_SECRET_KEY. Stage 2 accepts Stripe TEST keys only (sk_test_...).");
  process.exit(1);
}
if (!process.env.APP_BASE_URL) {
  console.error("Set APP_BASE_URL in .env, e.g. http://localhost:3000");
  process.exit(1);
}
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

function saveEvent(event) {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  let events = [];
  try { events = JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); } catch (_) {}
  events.unshift(event);
  fs.writeFileSync(DATA_FILE, JSON.stringify(events.slice(0, 500), null, 2));
}

// Stripe requires the raw request body for signature verification.
app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), (req, res) => {
  const signature = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, signature, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Webhook signature verification failed:", err.message);
    return res.status(400).send("Invalid webhook signature");
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    saveEvent({
      id: event.id,
      checkout_session: session.id,
      payment_intent: session.payment_intent || null,
      status: session.payment_status === "paid" ? "approved" : "processing",
      amount_total: session.amount_total,
      currency: session.currency,
      created_at: new Date().toISOString(),
      source: "stripe_test_webhook"
    });
  } else if (event.type === "checkout.session.async_payment_failed") {
    const session = event.data.object;
    saveEvent({
      id: event.id, checkout_session: session.id,
      status: "declined", created_at: new Date().toISOString(),
      source: "stripe_test_webhook"
    });
  } else if (event.type === "payment_intent.payment_failed") {
    const intent = event.data.object;
    saveEvent({
      id: event.id, payment_intent: intent.id,
      status: "declined", created_at: new Date().toISOString(),
      source: "stripe_test_webhook"
    });
  }
  res.json({ received: true });
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(rateLimit({ windowMs: 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));

app.get("/api/config", (_req, res) => {
  res.json({ paymentProvider: "Stripe", mode: "test", enabled: true, amount: 100, currency: "usd" });
});

// BIN is optional metadata only. The application never generates or probes card numbers.
app.post("/api/checkout/session", async (req, res) => {
  try {
    const binPrefix = String(req.body.binPrefix || "").trim();
    if (binPrefix && !/^\d{5,8}$/.test(binPrefix)) {
      return res.status(400).json({ error: "BIN prefix must contain 5 to 8 digits." });
    }

    const base = process.env.APP_BASE_URL.replace(/\/$/, "");
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [{
        price_data: {
          currency: "usd",
          product_data: { name: "Authorized Sandbox Payment Test" },
          unit_amount: 100
        },
        quantity: 1
      }],
      metadata: {
        app: "SHADOW_CARD_LAB_V99",
        environment: "test",
        bin_prefix: binPrefix || "not_provided"
      },
      success_url: `${base}/?payment=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${base}/?payment=cancelled`
    });
    res.json({ url: session.url, id: session.id });
  } catch (err) {
    console.error("Checkout creation failed:", err.message);
    res.status(502).json({ error: "Could not create a test checkout session. Check your Stripe test key and configuration." });
  }
});

app.get("/api/checkout/status", async (req, res) => {
  try {
    const id = String(req.query.session_id || "");
    if (!id.startsWith("cs_test_")) return res.status(400).json({ error: "Invalid test session id." });
    const session = await stripe.checkout.sessions.retrieve(id);
    res.json({
      session_id: session.id,
      payment_status: session.payment_status,
      status: session.status,
      amount_total: session.amount_total,
      currency: session.currency
    });
  } catch (err) {
    res.status(404).json({ error: "Test checkout session not found." });
  }
});

app.get("/api/events", (_req, res) => {
  try {
    const events = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    res.json(events.slice(0, 50));
  } catch (_) {
    res.json([]);
  }
});

app.use(express.static(path.join(__dirname, "public")));
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`SHADOW CARD LAB V99 running at http://localhost:${PORT}`));
