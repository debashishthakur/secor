const express = require("express");
const { PrismaClient } = require("@prisma/client");
const Member = require("./models/member");
const Account = require("./models/account");

const prisma = new PrismaClient();
const app = express();

// Prisma select.
app.get("/api/users/:id", async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.params.id }, select: { id: true, email: true } });
  res.json(user);
});

// Prisma omit.
app.get("/api/users", async (req, res) => {
  res.json(await prisma.user.findMany({ omit: { passwordHash: true } }));
});

// Mongoose: sensitive fields are select: false in the schema.
app.get("/api/members/:id", async (req, res) => {
  res.json(await Member.findById(req.params.id));
});

// Mongoose projection with .select().
app.get("/api/accounts/:id", async (req, res) => {
  const account = await Account.findById(req.params.id).select("-password");
  res.json(account);
});

// Sensitive field overwritten in the copy.
app.get("/api/me", async (req, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.user.id } });
  res.json({ ...me, passwordHash: undefined });
});

// Unknown model (not in the schema): not a finding.
app.get("/api/audit", async (req, res) => {
  res.json(await prisma.auditLog.findMany());
});

module.exports = app;
