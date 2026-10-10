const express = require("express");
const { requireAuth } = require("../auth");
const prisma = require("../db");
const Order = require("../models/order");

const router = express.Router();

router.get("/notes/:id", requireAuth, async (req, res) => {
  const note = await prisma.note.findUnique({ where: { id: req.params.id } });
  res.json(note);
});

router.delete("/orders/:orderId", requireAuth, async (req, res) => {
  const { orderId } = req.params;
  await Order.findByIdAndDelete(orderId);
  res.sendStatus(204);
});

module.exports = router;
