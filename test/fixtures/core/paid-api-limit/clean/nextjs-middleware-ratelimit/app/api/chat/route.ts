import { streamText } from "ai";
import { anthropic } from "@ai-sdk/anthropic";

export async function POST(req: Request) {
  const { messages } = await req.json();
  return streamText({ model: anthropic("claude-x"), messages }).toDataStreamResponse();
}
