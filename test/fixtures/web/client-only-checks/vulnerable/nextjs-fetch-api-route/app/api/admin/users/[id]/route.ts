import { auth } from "@/auth";
import { db } from "@/lib/db";

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { id } = await ctx.params;
  await db.user.delete({ where: { id } });
  return new Response(null, { status: 204 });
}
