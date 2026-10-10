import express from "express";
import Anthropic from "@anthropic-ai/sdk";
import { requireAuth } from "./auth";

const app = express();
const anthropic = new Anthropic();

app.post("/api/summarize", requireAuth, async (req, res) => {
  const out = await anthropic.messages.create({ model: "claude-x", max_tokens: 400, messages: [{ role: "user", content: req.body.text }] });
  res.json(out);
});

export default app;
