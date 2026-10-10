"use server";

import { z } from "zod";
import { auth } from "@/auth";
import { prisma } from "@/lib/db";

const TodoInput = z.object({ title: z.string().min(1).max(200) });

export async function createTodo(formData: FormData) {
  const session = await auth();
  if (!session?.user) throw new Error("Unauthorized");
  const { title } = TodoInput.parse({ title: formData.get("title") });
  await prisma.todo.create({ data: { title, userId: session.user.id } });
}
