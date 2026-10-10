import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export async function POST() {
  (await cookies()).set("session", "v", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax" });
  const res = NextResponse.json({ ok: true });
  res.cookies.set({ name: "refresh_token", value: "v", httpOnly: true, secure: true, sameSite: "strict" });
  return res;
}
