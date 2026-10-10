import OpenAI from "openai";
import { ratelimit } from "../../../lib/ratelimit";

const openai = new OpenAI();

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for") ?? "anon";
  const { success } = await ratelimit.limit(ip);
  if (!success) return new Response("Too many requests", { status: 429 });
  const { messages } = await req.json();
  return Response.json(await openai.chat.completions.create({ model: "gpt-4o-mini", messages }));
}
