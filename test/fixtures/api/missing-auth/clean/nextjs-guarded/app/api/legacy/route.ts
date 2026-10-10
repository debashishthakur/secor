import { getServerSession } from "next-auth";

export async function DELETE() {
  const session = await getServerSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
  return new Response(null, { status: 204 });
}
