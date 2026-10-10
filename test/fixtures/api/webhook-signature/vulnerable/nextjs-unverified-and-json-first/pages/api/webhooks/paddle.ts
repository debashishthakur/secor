import type { NextApiRequest, NextApiResponse } from "next";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const event = req.body;
  if (event.event_type === "subscription.created") await activate(event.data);
  res.status(200).json({ ok: true });
}
