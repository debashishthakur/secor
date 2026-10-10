const express = require("express");
const { fulfillOrder } = require("./orders");

const app = express();

app.post("/webhooks/stripe", express.json(), async (req, res) => {
  const event = req.body;
  if (event.type === "checkout.session.completed") await fulfillOrder(event.data.object);
  res.json({ received: true });
});

module.exports = app;
