import OpenAI from "openai";

const server = new OpenAI({ dangerouslyAllowBrowser: true });

export async function POST() {
  return Response.json(await server.models.list());
}
