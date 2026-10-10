"use server";

import { auth } from "@/auth";

export async function renameProject(id: string, name: string) {
  const session = await auth();
  if (!session) throw new Error("Unauthorized");
  return { id, name };
}
