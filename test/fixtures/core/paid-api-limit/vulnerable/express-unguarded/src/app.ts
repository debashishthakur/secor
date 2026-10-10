import express from "express";
import OpenAI from "openai";

const app = express();
const openai = new OpenAI();

app.post("/api/chat", async (req, res) => {
  const completion = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: req.body.messages });
  res.json(completion);
});

export default app;
