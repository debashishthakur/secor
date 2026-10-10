import { NextResponse } from "next/server";
import { auth } from "@/auth";

export default auth((req) => {
  if (!req.auth) return NextResponse.redirect(new URL("/login", req.url));
});

export const config = { matcher: ["/api/admin/:path*", "/dashboard/:path*"] };
