const crypto = require("node:crypto");
const express = require("express");
const Stripe = require("stripe");

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

app.post("/webhooks/stripe", express.raw({ type: "application/json" }), (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send("Invalid signature");
  }
  res.json({ received: event.id });
});

function verifyGithubSignature(req) {
  const expected = "sha256=" + crypto.createHmac("sha256", process.env.GITHUB_WEBHOOK_SECRET).update(req.body).digest("hex");
  const given = String(req.headers["x-hub-signature-256"] || "");
  return given.length === expected.length && crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected));
}

app.post("/webhooks/github", express.raw({ type: "application/json" }), (req, res) => {
  if (!verifyGithubSignature(req)) return res.sendStatus(400);
  res.sendStatus(204);
});

module.exports = app;
