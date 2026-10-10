const express = require("express");
const Member = require("./models/member");

const app = express();

app.get("/api/members/:id", async (req, res) => {
  res.json(await Member.findById(req.params.id));
});

module.exports = app;
