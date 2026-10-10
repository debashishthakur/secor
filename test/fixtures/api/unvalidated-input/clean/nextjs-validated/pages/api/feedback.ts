import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { prisma } from "@/lib/db";

const Feedback = z.object({ message: z.string().max(2000), rating: z.number().int().min(1).max(5) });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();
  const data = Feedback.parse(req.body);
  await prisma.feedback.create({ data });
  res.status(201).end();
}
