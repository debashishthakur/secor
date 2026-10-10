import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "");

export async function POST(req: Request) {
  const body = await req.text();
  const signature = req.headers.get("stripe-signature") ?? "";
  try {
    const event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET ?? "");
    return Response.json({ received: event.id });
  } catch {
    return new Response("Invalid signature", { status: 400 });
  }
}
