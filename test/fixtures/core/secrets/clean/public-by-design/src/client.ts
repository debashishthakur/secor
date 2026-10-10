// Values that are public by design: shipped to browsers on purpose.
export const stripe = { stripeApiKey: "__FAKE_STRIPE_PUBLISHABLE__" };
export const supabase = { supabaseApiKey: "__FAKE_SUPABASE_PUBLISHABLE__", anonToken: "__FAKE_ANON_JWT__" };
export const firebaseConfig = {
  apiKey: "__FAKE_GOOGLE__",
  authDomain: "demo-app.firebaseapp.com",
  projectId: "demo-app",
};
export const posthog = { posthogApiKey: "__FAKE_POSTHOG__" };
export const sentry = { dsn: "https://abcdef0123456789abcdef0123456789@o123456.ingest.sentry.io/7654321" };
