import { NextResponse, type NextRequest } from "next/server";

const ALLOWED = new Set(["https://app.example.com"]);

export function middleware(request: NextRequest) {
  const origin = request.headers.get("origin") ?? "";
  const response = NextResponse.next();
  if (ALLOWED.has(origin)) {
    response.headers.set("Access-Control-Allow-Origin", origin);
    response.headers.set("Access-Control-Allow-Credentials", "true");
  }
  return response;
}

export const config = { matcher: "/api/:path*" };
