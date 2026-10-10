import { Webhook } from "svix";

const wh = new Webhook(process.env.RESEND_WEBHOOK_SECRET ?? "");

export async function POST(req: Request) {
  const payload = await req.text();
  const headers = Object.fromEntries(req.headers);
  try {
    const evt = wh.verify(payload, headers);
    return Response.json({ ok: true, evt });
  } catch {
    return new Response("Invalid signature", { status: 400 });
  }
}
