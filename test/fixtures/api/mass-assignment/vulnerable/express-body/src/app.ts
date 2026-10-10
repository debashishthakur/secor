import express from "express";
import { prisma } from "./db";
import { Post, Profile } from "./models";
import { requireAuth } from "./auth";

export const app = express();
app.use(express.json());

app.put("/api/users/me", requireAuth, async (req, res) => {
  const user = await prisma.user.update({ where: { id: req.user.id }, data: req.body });
  res.json({ id: user.id });
});

app.post("/api/posts", requireAuth, async (req, res) => {
  const post = await Post.create({ ...req.body, author: req.user.id });
  res.status(201).json({ id: post.id });
});

app.post("/api/profiles", requireAuth, async (req, res) => {
  const input = req.body;
  const profile = new Profile(input);
  await profile.save();
  res.status(201).end();
});

app.patch("/api/profiles/:id", requireAuth, async (req, res) => {
  await Profile.findByIdAndUpdate(req.params.id, { $set: req.body });
  res.sendStatus(204);
});
