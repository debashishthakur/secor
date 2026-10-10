import express from "express";
import usersRouter from "./routes/users";
import { createAdminRouter } from "./routes/admin";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import passport from "passport";

const app = express();
const bearer = requireBearerAuth({ verifier: {} as never });

app.get("/health", (_req, res) => res.json({ ok: true }));
app.post("/login", (req, res) => res.json({}));
app.use("/api/users", usersRouter);
app.use("/admin", createAdminRouter());
app.get("/jwt", passport.authenticate("jwt", { session: false }), (req, res) => res.json(req.user));
app.all("/mcp", bearer, express.json(), async (req, res) => res.end());
app.get(["/a", "/b"], (_req, res) => res.end());
app.route("/items/:id(\\d+)").get((req, res) => res.end()).delete((req, res) => res.end());
app.get("title"); // settings getter, not a route
app.use(requireAuth);
app.get("/after-guard", (req, res) => res.json(req.user));

function requireAuth(req: any, res: any, next: any) { next(); }
export default app;
