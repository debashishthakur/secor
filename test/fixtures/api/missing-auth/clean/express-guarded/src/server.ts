import path from "node:path";
import express from "express";
import passport from "passport";
import { toNodeHandler } from "better-auth/node";
import { auth, requireBearerAuth, requireAuth } from "./auth";
import billing from "./billing";

export const app = express();
const bearer = requireBearerAuth({ verifier: tokenVerifier });

app.all("/api/auth/*splat", toNodeHandler(auth));
app.get("/status", (req, res) => res.json({ up: true }));
app.options("/api/items", (req, res) => res.sendStatus(204));
// SPA fallback: serves the client bundle, not an API entry point.
app.get("/app/*splat", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/api/me", bearer, (req, res) => res.json(req.user));
app.post("/api/login", passport.authenticate("local"), (req, res) => res.json({ ok: true }));
app.use("/api/billing", requireAuth, billing);
app.use(requireAuth);
app.get("/api/orders", (req, res) => res.json([]));
