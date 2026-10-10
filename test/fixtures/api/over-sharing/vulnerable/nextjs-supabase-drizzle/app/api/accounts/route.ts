import { db } from "@/db";
import { accounts } from "@/db/schema";

export async function GET() {
  const rows = await db.select().from(accounts);
  return Response.json(rows);
}
