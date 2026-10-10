const express = require("express");

const app = express();

app.get("/items", async (req, res) => {
  res.json([]);
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message, stack: err.stack });
});

module.exports = app;
