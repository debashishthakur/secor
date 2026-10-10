import { formatName } from "@/lib/server/helpers";
export async function GET() { return Response.json({ name: formatName(" x ") }); }
