const express = require("express");
const { prisma, db } = require("./db");
const { requireAuth } = require("./auth");

const app = express();
app.use(express.json());

app.post("/api/posts", requireAuth, async (req, res) => {
  const post = await prisma.post.create({ data: { title: req.body.title, body: req.body.body, authorId: req.user.id } });
  res.status(201).json({ id: post.id });
});

app.patch("/api/posts/:id", requireAuth, async (req, res) => {
  const { title } = req.body;
  await db.query("UPDATE posts SET title = $1 WHERE id = $2", [title, req.params.id]);
  res.sendStatus(204);
});

module.exports = app;
