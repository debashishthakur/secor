import { eq } from "drizzle-orm";
import { auth } from "@/auth";
import { db } from "@/db";
import { settings } from "@/db/schema";

export async function PATCH(request: Request) {
  const session = await auth();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  await db.update(settings).set(await request.json()).where(eq(settings.userId, session.user.id));
  return new Response(null, { status: 204 });
}
