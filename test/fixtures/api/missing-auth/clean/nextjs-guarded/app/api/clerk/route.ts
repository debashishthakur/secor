import { auth } from "@clerk/nextjs/server";

export async function POST() {
  const { userId } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });
  return Response.json({ ok: true });
}
