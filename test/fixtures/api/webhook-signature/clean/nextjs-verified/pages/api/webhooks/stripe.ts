import type { NextApiRequest, NextApiResponse } from "next";
import { buffer } from "micro";
import Stripe from "stripe";

export const config = { api: { bodyParser: false } };

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "");

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const raw = await buffer(req);
  try {
    const event = stripe.webhooks.constructEvent(raw, String(req.headers["stripe-signature"]), process.env.STRIPE_WEBHOOK_SECRET ?? "");
    res.json({ received: event.id });
  } catch {
    res.status(400).send("Invalid signature");
  }
}
