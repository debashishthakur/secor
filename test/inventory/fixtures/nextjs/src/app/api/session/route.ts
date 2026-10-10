import { withAuth } from "@/lib/with-auth";
export const PATCH = withAuth(async (req: Request) => Response.json({}));
