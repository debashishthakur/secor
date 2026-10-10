import { createClient } from "@/lib/supabase/server";

// RLS on notes (supabase/migrations) ties every row to auth.uid().
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { id } = await params;
  await supabase.from("notes").delete().eq("id", id);
  return new Response(null, { status: 204 });
}
