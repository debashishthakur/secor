const express = require("express");
const { z } = require("zod");
const Joi = require("joi");
const { prisma } = require("./db");
const { requireAuth, validate } = require("./middleware");

const app = express();
app.use(express.json());

const PostInput = z.object({ title: z.string().min(1).max(200) });
const CommentInput = Joi.object({ text: Joi.string().max(1000).required() });

// zod
app.post("/api/posts", requireAuth, async (req, res) => {
  const { title } = PostInput.parse(req.body);
  const post = await prisma.post.create({ data: { title, authorId: req.user.id } });
  res.status(201).json({ id: post.id });
});

// joi
app.post("/api/comments", requireAuth, async (req, res) => {
  const { value, error } = CommentInput.validate(req.body);
  if (error) return res.status(400).json({ error: error.message });
  await prisma.comment.create({ data: { text: value.text, authorId: req.user.id } });
  res.sendStatus(201);
});

// validation middleware on the route
app.post("/api/tags", requireAuth, validate(PostInput), async (req, res) => {
  await prisma.tag.create({ data: { name: req.body.title } });
  res.sendStatus(201);
});

// The whole body: reported by api/mass-assignment, not here.
app.post("/api/drafts", requireAuth, async (req, res) => {
  await prisma.draft.create({ data: req.body });
  res.sendStatus(201);
});

module.exports = app;
