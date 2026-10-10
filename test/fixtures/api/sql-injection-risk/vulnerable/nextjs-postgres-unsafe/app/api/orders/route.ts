import type { NextRequest } from "next/server";
import { sql } from "@/lib/db";

export async function GET(req: NextRequest) {
  const status = req.nextUrl.searchParams.get("status");
  const rows = await sql.unsafe(`SELECT * FROM orders WHERE status = '${status}'`);
  return Response.json(rows);
}
