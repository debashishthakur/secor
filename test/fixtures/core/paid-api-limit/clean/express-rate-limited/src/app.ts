import express from "express";
import rateLimit from "express-rate-limit";
import OpenAI from "openai";

const app = express();
const openai = new OpenAI();
const limiter = rateLimit({ windowMs: 60_000, limit: 20 });

app.use("/api", limiter);

app.post("/api/chat", async (req, res) => {
  res.json(await openai.chat.completions.create({ model: "gpt-4o-mini", messages: req.body.messages }));
});

app.post("/admin/images", rateLimit({ windowMs: 60_000, limit: 5 }), async (req, res) => {
  res.json(await openai.images.generate({ prompt: req.body.prompt }));
});

export default app;
