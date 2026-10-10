import { z } from "zod";
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

const CommentInput = z.object({ text: z.string().min(1).max(1000), postId: z.string().cuid() });

export async function POST(request: Request) {
  const session = await auth();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  const parsed = CommentInput.safeParse(await request.json());
  if (!parsed.success) return Response.json(parsed.error.flatten(), { status: 400 });
  await prisma.comment.create({ data: { ...parsed.data, authorId: session.user.id } });
  return new Response(null, { status: 201 });
}
