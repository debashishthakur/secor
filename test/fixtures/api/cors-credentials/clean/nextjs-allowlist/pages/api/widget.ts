import type { NextApiRequest, NextApiResponse } from "next";

const ALLOWED = ["https://partner.example.com"];

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const origin = req.headers.origin ?? "";
  if (ALLOWED.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.json({ ok: true });
}
