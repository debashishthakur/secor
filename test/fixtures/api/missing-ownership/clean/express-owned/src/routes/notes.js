const express = require("express");
const { requireAuth, requireAdmin } = require("../auth");
const prisma = require("../db");
const Order = require("../models/order");

const router = express.Router();

// The query filter references the signed-in user.
router.get("/notes/:id", requireAuth, async (req, res) => {
  const note = await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.id } });
  res.json(note);
});

// The loaded record's owner is compared with the signed-in user before responding.
router.get("/orders/:id", requireAuth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order || order.user.toString() !== req.user._id.toString()) return res.sendStatus(404);
  res.json(order);
});

// An earlier query on the same ID checks ownership before the update.
router.patch("/notes/:id", requireAuth, async (req, res) => {
  const existing = await prisma.note.findFirst({ where: { id: req.params.id, authorId: req.user.id } });
  if (!existing) return res.sendStatus(404);
  const note = await prisma.note.update({ where: { id: req.params.id }, data: { title: String(req.body.title) } });
  res.json(note);
});

// express-session identity in the filter.
router.get("/drafts/:id", requireAuth, async (req, res) => {
  res.json(await prisma.draft.findFirst({ where: { id: req.params.id, ownerId: req.session.userId } }));
});

// Admin-only route: an admin may load any record.
router.delete("/admin/orders/:id", requireAuth, requireAdmin, async (req, res) => {
  await Order.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});

// Not guarded: api/missing-auth covers it, ownership does not apply.
router.get("/public-notes/:id", async (req, res) => {
  res.json(await prisma.note.findUnique({ where: { id: req.params.id } }));
});

module.exports = router;
