import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const body = await req.json();
  const post = await prisma.post.create({ data: body });
  return Response.json({ id: post.id });
}
