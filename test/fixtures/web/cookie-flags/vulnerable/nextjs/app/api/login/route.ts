import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export async function POST() {
  const store = await cookies();
  store.set("session", "token-value", { httpOnly: true });
  const res = NextResponse.json({ ok: true });
  res.cookies.set("auth-token", "v");
  res.cookies.set({ name: "jwt", value: "v", httpOnly: true, secure: true, sameSite: "lax" });
  res.cookies.set("locale", "en");
  return res;
}
