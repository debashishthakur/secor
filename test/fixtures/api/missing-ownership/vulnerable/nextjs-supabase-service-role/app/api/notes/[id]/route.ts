import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";

// RLS applies: the user's own client.
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { id } = await params;
  const { data } = await supabase.from("notes").select("id, body").eq("id", id).single();
  return Response.json(data);
}

// RLS does not apply: the service-role client bypasses it.
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { id } = await params;
  const admin = createAdminClient();
  await admin.from("notes").delete().eq("id", id);
  return new Response(null, { status: 204 });
}
