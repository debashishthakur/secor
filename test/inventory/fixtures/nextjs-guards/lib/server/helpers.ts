import { createServerClient } from "@supabase/ssr";
export async function getServerProfile() {
  const supabase = createServerClient("u", "k", {} as never);
  const user = (await supabase.auth.getUser()).data.user;
  if (!user) throw new Error("User not found");
  return user;
}
export function formatName(n: string) { return n.trim(); }
