const express = require("express");
const cors = require("cors");

const ALLOWED = ["https://app.example.com", "https://admin.example.com"];
const app = express();

app.use(cors({ origin: ALLOWED, credentials: true }));
app.use("/public", cors({ origin: "*" }));
app.use("/api/v2", cors({ origin: (origin, cb) => cb(null, ALLOWED.includes(origin)), credentials: true }));

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  next();
});

app.get("/api/me", (req, res) => res.json({}));

module.exports = app;
