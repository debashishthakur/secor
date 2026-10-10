"use server";

import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function createTodo(formData: FormData) {
  const session = await auth();
  if (!session?.user) throw new Error("Unauthorized");
  await prisma.todo.create({ data: { title: String(formData.get("title")), userId: session.user.id } });
}
