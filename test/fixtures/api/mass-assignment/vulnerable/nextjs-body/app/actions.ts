"use server";

import { auth } from "@/auth";
import { prisma } from "@/lib/db";

type ProfileInput = { name: string; bio: string };

export async function updateProfile(data: ProfileInput) {
  const session = await auth();
  if (!session?.user) throw new Error("Unauthorized");
  await prisma.user.update({ where: { id: session.user.id }, data });
}
