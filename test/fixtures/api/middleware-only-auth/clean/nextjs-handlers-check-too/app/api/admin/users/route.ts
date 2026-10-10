import { auth } from "@/auth";
import { prisma } from "@/lib/db";

export async function GET() {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  return Response.json(await prisma.user.findMany({ select: { id: true, email: true } }));
}

export const DELETE = auth(async (req) => {
  if (!req.auth) return new Response("Unauthorized", { status: 401 });
  const { id } = await req.json();
  await prisma.user.delete({ where: { id } });
  return new Response(null, { status: 204 });
});
