import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "");

export async function POST(req: Request) {
  const body = await req.json();
  const signature = req.headers.get("stripe-signature") ?? "";
  const event: Stripe.Event = stripe.webhooks.constructEvent(JSON.stringify(body), signature, process.env.STRIPE_WEBHOOK_SECRET ?? "");
  return Response.json({ received: event.id });
}
