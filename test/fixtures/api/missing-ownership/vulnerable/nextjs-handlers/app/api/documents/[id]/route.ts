import { auth } from "@clerk/nextjs/server";
import { prisma } from "@/lib/db";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { userId } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });
  const { id } = await params;
  const doc = await prisma.document.findUnique({ where: { id } });
  return Response.json(doc);
}
