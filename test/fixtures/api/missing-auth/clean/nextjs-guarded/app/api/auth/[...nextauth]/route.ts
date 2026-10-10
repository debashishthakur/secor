// ADAPTER GAP (see api report): destructured route exports are not inventoried today.
// api/missing-auth excludes Auth.js handlers either way, so this case expects no finding regardless.
import { handlers } from "@/auth";

export const { GET, POST } = handlers;
