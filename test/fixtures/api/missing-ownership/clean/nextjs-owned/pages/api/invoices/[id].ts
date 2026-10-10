import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { prisma } from "@/lib/db";
import { authOptions } from "@/lib/auth";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) return res.status(401).end();
  const invoice = await prisma.invoice.findFirst({ where: { id: String(req.query.id), customerEmail: session.user.email } });
  res.json(invoice);
}
