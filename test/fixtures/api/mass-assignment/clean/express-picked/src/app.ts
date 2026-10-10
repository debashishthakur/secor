import express from "express";
import { z } from "zod";
import { prisma } from "./db";
import { requireAuth } from "./auth";

export const app = express();
app.use(express.json());

const ProfileInput = z.object({ name: z.string().max(80), bio: z.string().max(500) });

app.put("/api/users/me", requireAuth, async (req, res) => {
  const data = ProfileInput.parse(req.body);
  const user = await prisma.user.update({ where: { id: req.user.id }, data });
  res.json({ id: user.id });
});

app.post("/api/posts", requireAuth, async (req, res) => {
  const { title, body } = req.body;
  const post = await prisma.post.create({ data: { title: String(title), body: String(body), authorId: req.user.id } });
  res.status(201).json({ id: post.id });
});
