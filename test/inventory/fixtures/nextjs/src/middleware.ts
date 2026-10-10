import { auth } from "@/auth";
export default auth((req) => {});
export const config = { matcher: ["/api/files/:path*", "/dashboard/:path*"] };
