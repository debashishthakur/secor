"use server";

import { prisma } from "@/lib/db";

export async function deleteNote(id: string) {
  await prisma.note.delete({ where: { id } });
}
