"use client";

import OpenAI from "openai";

const client = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});

export default function Assistant() {
  return <button onClick={() => client.responses.create({ model: "gpt-4.1", input: "hi" })}>Ask</button>;
}
