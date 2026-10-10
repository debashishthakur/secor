import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function POST(req: Request) {
  const session = await auth();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  const { title } = await req.json();
  const post = await prisma.post.create({ data: { title: String(title), authorId: session.user.id } });
  return Response.json({ id: post.id });
}
