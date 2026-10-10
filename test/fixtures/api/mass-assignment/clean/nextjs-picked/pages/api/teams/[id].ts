import type { NextApiRequest, NextApiResponse } from "next";
import { prisma } from "@/lib/db";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "PUT") {
    const { name } = req.body;
    const team = await prisma.team.update({ where: { id: String(req.query.id) }, data: { name: String(name) } });
    return res.json({ id: team.id });
  }
  res.status(405).end();
}
