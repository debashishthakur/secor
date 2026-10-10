const express = require("express");
const session = require("express-session");

const app = express();

app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));

app.post("/login", (req, res) => {
  res.cookie("session_token", "abc", { maxAge: 3600000 });
  res.cookie("theme", "dark");
  res.cookie("csrf_token", "t");
  res.json({ ok: true });
});

app.post("/refresh", (req, res) => {
  res.cookie("refresh", "x", {
    httpOnly: true,
    secure: false,
  });
  res.end();
});

module.exports = app;
