import { prisma } from "@/lib/db";

export async function GET() {
  return Response.json(await prisma.user.findMany({ select: { id: true, email: true } }));
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await prisma.user.delete({ where: { id } });
  return new Response(null, { status: 204 });
}
