"use server";

import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function updateProfile(formData: FormData) {
  const session = await auth();
  if (!session?.user) throw new Error("Unauthorized");
  await prisma.user.update({ where: { id: session.user.id }, data: { name: String(formData.get("name")) } });
}
