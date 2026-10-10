const express = require("express");
const { PrismaClient } = require("@prisma/client");
const { requireAuth } = require("./auth");

const prisma = new PrismaClient();
const app = express();

app.get("/api/users/:id", requireAuth, async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.params.id } });
  res.json(user);
});

app.get("/api/team", requireAuth, async (req, res) => {
  const members = await prisma.user.findMany({ include: { posts: true } });
  res.status(200).json({ members });
});

app.get("/api/me", requireAuth, async (req, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.user.id } });
  res.json({ ...me, isMe: true });
});

// Post has no sensitive field: not a finding.
app.get("/api/posts", async (req, res) => {
  res.json(await prisma.post.findMany());
});

module.exports = app;
