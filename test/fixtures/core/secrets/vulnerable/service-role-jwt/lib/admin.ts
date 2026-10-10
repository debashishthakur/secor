import { createClient } from "@supabase/supabase-js";

export const admin = createClient(
  "https://demo.supabase.co",
  "__FAKE_SERVICE_ROLE_JWT__",
);
