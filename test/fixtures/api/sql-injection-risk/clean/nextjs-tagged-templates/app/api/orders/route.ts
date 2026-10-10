import type { NextRequest } from "next/server";
import { sql as drizzleSql } from "drizzle-orm";
import { db } from "@/db";
import { sql } from "@/lib/db";

export async function GET(req: NextRequest) {
  const status = req.nextUrl.searchParams.get("status");
  const rows = await sql`SELECT * FROM orders WHERE status = ${status}`;
  return Response.json(rows);
}

export async function DELETE(req: NextRequest) {
  const id = req.nextUrl.searchParams.get("id");
  await db.execute(drizzleSql`DELETE FROM orders WHERE id = ${id}`);
  return new Response(null, { status: 204 });
}
