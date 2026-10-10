import type { WebhookEvent } from "@clerk/nextjs/server";
import { createUser } from "@/lib/users";

export async function POST(req: Request) {
  const evt = (await req.json()) as WebhookEvent;
  if (evt.type === "user.created") await createUser(evt.data);
  return new Response("ok");
}
