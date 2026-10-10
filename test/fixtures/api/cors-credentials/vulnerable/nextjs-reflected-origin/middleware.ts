import { NextResponse, type NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  const origin = request.headers.get("origin") ?? "";
  const response = NextResponse.next();
  response.headers.set("Access-Control-Allow-Origin", origin);
  response.headers.set("Access-Control-Allow-Credentials", "true");
  return response;
}

export const config = { matcher: "/api/:path*" };
