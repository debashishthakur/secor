import type { NextApiRequest, NextApiResponse } from "next";
import { prisma } from "@/lib/db";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const customer = await prisma.customer.findUnique({ where: { id: String(req.query.id) }, select: { id: true, email: true } });
  res.status(200).json(customer);
}
