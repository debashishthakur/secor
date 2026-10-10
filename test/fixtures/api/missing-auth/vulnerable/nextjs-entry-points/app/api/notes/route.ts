import { prisma } from "@/lib/db";

export async function GET() {
  const notes = await prisma.note.findMany();
  return Response.json(notes);
}

export async function OPTIONS() {
  return new Response(null, { status: 204 });
}
