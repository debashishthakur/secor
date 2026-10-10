const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors({ origin: true, credentials: true }));

const v2Options = { origin: (origin, callback) => callback(null, true), credentials: true };
app.use("/api/v2", cors(v2Options));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

app.get("/api/me", (req, res) => res.json({}));

module.exports = app;
