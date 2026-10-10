import { auth } from "@clerk/nextjs/server";
import OpenAI from "openai";

const openai = new OpenAI();

export async function POST(req: Request) {
  const { userId } = await auth();
  const { messages } = await req.json();
  const completion = await openai.chat.completions.create({ model: "gpt-4o-mini", messages, user: userId ?? "anon" });
  return Response.json(completion);
}
