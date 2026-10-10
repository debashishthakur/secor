import { getServerProfile } from "@/lib/server/helpers";
export async function GET() {
  const profile = await getServerProfile();
  return Response.json(profile);
}
