const express = require("express");
const { execute } = require("./jobs");
const { pool, knex, prisma } = require("./db");

const app = express();

app.get("/api/users/:id", async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  res.json(rows);
});

app.get("/api/accounts/:id", async (req, res) => {
  const rows = await prisma.$queryRaw`SELECT * FROM accounts WHERE id = ${req.params.id}`;
  res.json(rows);
});

app.get("/api/ping", async (req, res) => {
  res.json(await knex.raw("select 1"));
});

app.post("/api/jobs/:name", async (req, res) => {
  // Not SQL: a template literal passed to an unrelated execute().
  res.json(await execute(`${req.params.name}.job`));
});

module.exports = app;
