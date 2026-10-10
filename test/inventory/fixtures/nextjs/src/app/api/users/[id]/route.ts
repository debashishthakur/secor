import { auth } from "@/auth";
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth();
  if (!session) return new Response("no", { status: 401 });
  return Response.json({ id: (await params).id });
}
export const DELETE = async () => new Response(null, { status: 204 });
