import { verifyWebhook } from "@clerk/nextjs/webhooks";
import type { NextRequest } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const evt = await verifyWebhook(req);
    return Response.json({ type: evt.type });
  } catch {
    return new Response("Invalid signature", { status: 400 });
  }
}
