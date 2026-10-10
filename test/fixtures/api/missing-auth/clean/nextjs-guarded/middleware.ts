import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";

const isAdmin = createRouteMatcher(["/api/admin(.*)"]);

export default clerkMiddleware(async (auth, req) => {
  if (isAdmin(req)) await auth.protect();
});

export const config = { matcher: ["/api/admin/:path*"] };
