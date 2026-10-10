import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import { NextResponse, type NextRequest } from "next/server";

const ratelimit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.fixedWindow(20, "60 s") });

export async function middleware(request: NextRequest) {
  const { success } = await ratelimit.limit(request.headers.get("x-forwarded-for") ?? "anon");
  return success ? NextResponse.next() : new NextResponse("Too many requests", { status: 429 });
}

export const config = { matcher: ["/api/:path*"] };
