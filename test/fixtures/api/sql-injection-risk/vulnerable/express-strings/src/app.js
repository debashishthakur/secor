const express = require("express");
const { pool, knex, prisma } = require("./db");
const { findOrdersByStatus } = require("./repo");

const app = express();

app.get("/api/users", async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  res.json(rows);
});

app.get("/api/search", async (req, res) => {
  const sql = "SELECT * FROM products WHERE title LIKE '%" + req.query.q + "%'";
  res.json(await knex.raw(sql));
});

app.delete("/api/logs", async (req, res) => {
  await prisma.$executeRawUnsafe("DELETE FROM logs WHERE id = " + req.body.id);
  res.sendStatus(204);
});

app.get("/api/orders", async (req, res) => res.json(await findOrdersByStatus(req.query.status)));

module.exports = app;
