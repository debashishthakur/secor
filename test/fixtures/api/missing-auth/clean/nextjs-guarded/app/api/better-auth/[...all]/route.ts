// ADAPTER GAP (see api report): destructured route exports are not inventoried today.
// api/missing-auth excludes better-auth handlers either way, so this case expects no finding regardless.
import { toNextJsHandler } from "better-auth/next-js";
import { auth } from "@/lib/better-auth";

export const { GET, POST } = toNextJsHandler(auth);
