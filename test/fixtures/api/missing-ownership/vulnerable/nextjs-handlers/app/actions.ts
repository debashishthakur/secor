"use server";

import { getServerSession } from "next-auth";
import { prisma } from "@/lib/db";

export async function archivePost(postId: string) {
  const session = await getServerSession();
  if (!session?.user) throw new Error("Unauthorized");
  await prisma.post.update({ where: { id: postId }, data: { archived: true } });
}
