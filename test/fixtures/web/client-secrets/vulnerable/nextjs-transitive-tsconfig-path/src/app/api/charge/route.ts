const STRIPE_KEY = "__FAKE_STRIPE_LIVE__";

export async function POST() {
  return Response.json({ ok: STRIPE_KEY.length > 0 });
}
