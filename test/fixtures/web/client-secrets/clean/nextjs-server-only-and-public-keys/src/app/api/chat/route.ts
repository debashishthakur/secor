const ANTHROPIC_KEY = "__FAKE_ANTHROPIC__";

export async function POST() {
  return Response.json({ ok: ANTHROPIC_KEY.length > 0 });
}
