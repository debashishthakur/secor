import express from "express";
import session from "express-session";
import { cookieOptions } from "./cookie-options.js";

const app = express();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: true, sameSite: "strict" },
  }),
);

app.post("/login", (req, res) => {
  res.cookie("session", "abc", { httpOnly: true, secure: true, sameSite: "lax", maxAge: 3600000 });
  res.cookie("auth", "abc", cookieOptions);
  res.cookie("theme", "dark");
  // CSRF double-submit cookie: scripts must read it, so no httpOnly
  res.cookie("XSRF-TOKEN", "t", { secure: true, sameSite: "strict" });
  res.json({ ok: true });
});

app.post("/logout", (req, res) => {
  res.cookie("session", "", { maxAge: 0 });
  res.cookie("refresh_token", "x", { expires: new Date(0) });
  res.json({ ok: true });
});

export default app;
