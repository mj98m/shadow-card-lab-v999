
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });

async function stripeRequest(path, secret, options = {}) {
  const response = await fetch(
    `https://api.stripe.com/v1/${path}`,
    {
      method: options.method || "GET",
      headers: {
        Authorization: `Bearer ${secret}`,
        ...(options.body
          ? { "Content-Type": "application/x-www-form-urlencoded" }
          : {})
      },
      body: options.body
    }
  );

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error?.message || "Stripe request failed");
  }

  return data;
}

async function verifyWebhook(rawBody, signature, secret) {
  if (!signature || !secret) return false;

  const fields = signature.split(",").map(part => {
    const i = part.indexOf("=");
    return [
      part.slice(0, i).trim(),
      part.slice(i + 1).trim()
    ];
  });

  const timestamp = Number(
    fields.find(([key]) => key === "t")?.[1]
  );

  const signatures = fields
    .filter(([key]) => key === "v1")
    .map(([, value]) => value);

  if (
    !timestamp ||
    Math.abs(Date.now() / 1000 - timestamp) > 300 ||
    signatures.length === 0
  ) {
    return false;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signed = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${timestamp}.${rawBody}`)
  );

  const expected = [...new Uint8Array(signed)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  return signatures.some(value => {
    if (value.length !== expected.length) return false;

    let diff = 0;

    for (let i = 0; i < value.length; i++) {
      diff |= value.charCodeAt(i) ^ expected.charCodeAt(i);
    }

    return diff === 0;
  });
}

async function ensureSchema(env) {
  if (!env.DB) {
    throw new Error("D1 database is not connected");
  }

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id TEXT NOT NULL UNIQUE,
      event_type TEXT NOT NULL,
      payload TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_events_created_at
    ON events(created_at)
  `).run();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (
        env.DB &&
        ["/api/events", "/api/stripe/webhook"].includes(url.pathname)
      ) {
        await ensureSchema(env);
      }

      if (
        url.pathname === "/api/config" &&
        request.method === "GET"
      ) {
        return json({
          paymentProvider: "Stripe",
          mode: "test",
          enabled: Boolean(
            env.STRIPE_SECRET_KEY?.startsWith("sk_test_")
          ),
          amount: 100,
          currency: "usd"
        });
      }

      if (
        url.pathname === "/api/checkout/session" &&
        request.method === "POST"
      ) {
        if (!env.STRIPE_SECRET_KEY?.startsWith("sk_test_")) {
          return json({
            error: "Stripe test mode is not configured"
          }, 503);
        }

        const input = await request.json().catch(() => ({}));
        const binPrefix = String(input.binPrefix || "").trim();

        if (binPrefix && !/^\d{5,8}$/.test(binPrefix)) {
          return json({
            error: "BIN prefix must contain 5 to 8 digits"
          }, 400);
        }

        const form = new URLSearchParams();

        form.set("mode", "payment");
        form.set(
          "success_url",
          `${url.origin}/?session_id={CHECKOUT_SESSION_ID}`
        );
        form.set("cancel_url", `${url.origin}/`);

        form.set("line_items[0][price_data][currency]", "usd");
        form.set(
          "line_items[0][price_data][product_data][name]",
          "Shadow Card Lab - Test Checkout"
        );
        form.set("line_items[0][price_data][unit_amount]", "100");
        form.set("line_items[0][quantity]", "1");

        form.set("metadata[bin_prefix]", binPrefix);
        form.set("metadata[environment]", "test");

        const session = await stripeRequest(
          "checkout/sessions",
          env.STRIPE_SECRET_KEY,
          {
            method: "POST",
            body: form.toString()
          }
        );

        return json({
          url: session.url,
          id: session.id
        });
      }

      if (
        url.pathname === "/api/checkout/status" &&
        request.method === "GET"
      ) {
        if (!env.STRIPE_SECRET_KEY?.startsWith("sk_test_")) {
          return json({
            error: "Stripe test mode is not configured"
          }, 503);
        }

        const id = url.searchParams.get("session_id") || "";

        if (!id.startsWith("cs_test_")) {
          return json({
            error: "Invalid test checkout session"
          }, 400);
        }

        const session = await stripeRequest(
          `checkout/sessions/${encodeURIComponent(id)}`,
          env.STRIPE_SECRET_KEY
        );

        return json({
          id: session.id,
          status: session.status,
          payment_status: session.payment_status,
          amount_total: session.amount_total,
          currency: session.currency
        });
      }

      if (
        url.pathname === "/api/stripe/webhook" &&
        request.method === "POST"
      ) {
        if (!env.DB) {
          return json({
            error: "D1 database is not connected"
          }, 503);
        }

        const rawBody = await request.text();

        const valid = await verifyWebhook(
          rawBody,
          request.headers.get("stripe-signature"),
          env.STRIPE_WEBHOOK_SECRET
        );

        if (!valid) {
          return json({
            error: "Invalid webhook signature"
          }, 400);
        }

        const event = JSON.parse(rawBody);

        const accepted = [
          "checkout.session.completed",
          "checkout.session.async_payment_failed",
          "payment_intent.payment_failed"
        ];

        if (accepted.includes(event.type)) {
          await env.DB.prepare(`
            INSERT OR IGNORE INTO events
            (event_id, event_type, payload, created_at)
            VALUES (?, ?, ?, ?)
          `)
            .bind(
              event.id,
              event.type,
              JSON.stringify(event.data?.object || {}),
              new Date().toISOString()
            )
            .run();
        }

        return json({ received: true });
      }

      if (
        url.pathname === "/api/events" &&
        request.method === "GET"
      ) {
        if (!env.DB) {
          return json({ events: [] });
        }

        const result = await env.DB.prepare(`
          SELECT event_id, event_type, payload, created_at
          FROM events
          ORDER BY id DESC
          LIMIT 50
        `).all();

        return json({
          events: result.results || []
        });
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response("Not found", { status: 404 });

    } catch (error) {
      return json({
        error: error.message || "Internal server error"
      }, 500);
    }
  }
};
