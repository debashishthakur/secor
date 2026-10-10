import { eq } from "drizzle-orm";
import { getServerSession } from "next-auth";
import { db } from "@/db";
import { projects } from "@/db/schema";

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const session = await getServerSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { id } = await ctx.params;
  const rows = await db.select().from(projects).where(eq(projects.id, Number(id)));
  return Response.json(rows);
}
