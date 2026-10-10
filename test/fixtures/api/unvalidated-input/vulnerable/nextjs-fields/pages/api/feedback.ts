import type { NextApiRequest, NextApiResponse } from "next";
import { prisma } from "@/lib/db";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();
  await prisma.feedback.create({ data: { message: req.body.message, rating: req.body.rating } });
  res.status(201).end();
}
