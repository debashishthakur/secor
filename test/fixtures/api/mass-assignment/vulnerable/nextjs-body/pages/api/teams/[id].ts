import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { prisma } from "@/lib/db";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, {});
  if (!session) return res.status(401).end();
  if (req.method === "PUT") {
    const team = await prisma.team.update({ where: { id: String(req.query.id) }, data: { ...req.body } });
    return res.json({ id: team.id });
  }
  res.status(405).end();
}
