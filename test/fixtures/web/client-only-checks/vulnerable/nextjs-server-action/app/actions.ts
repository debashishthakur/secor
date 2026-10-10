"use server";

import { auth } from "@/auth";
import { db } from "@/lib/db";

export async function deleteUser(id: string) {
  const session = await auth();
  if (!session) throw new Error("unauthorized");
  await db.user.delete({ where: { id } });
}
