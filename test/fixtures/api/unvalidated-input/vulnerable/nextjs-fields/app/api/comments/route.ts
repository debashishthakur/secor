import { auth } from "@/auth";
import { db } from "@/db";
import { comments } from "@/db/schema";

export async function POST(request: Request) {
  const session = await auth();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  const { text, postId } = await request.json();
  await db.insert(comments).values({ text, postId, authorId: session.user.id });
  return new Response(null, { status: 201 });
}
