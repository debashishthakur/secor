import express from "express";
import { requireAdmin, requireAuth } from "./auth";

const app = express();

app.delete("/api/posts/:id", requireAuth, requireAdmin, async (_req, res) => {
  res.sendStatus(204);
});

app.listen(3000);
