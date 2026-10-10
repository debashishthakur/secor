const express = require("express");
const notes = require("./routes/notes");
const { requireAuth } = require("./auth");

const app = express();
app.use(express.json());

app.get("/health", (req, res) => res.json({ ok: true }));
app.options("/api/things", (req, res) => res.sendStatus(204));
app.get("/api/users/:id", async (req, res) => {
  res.json(await db.user.findUnique({ where: { id: req.params.id } }));
});
app.use("/api/notes", notes);

// Routes registered after app.use(requireAuth) are guarded; the ones above are not.
app.use(requireAuth);
app.get("/api/settings", (req, res) => res.json({}));

module.exports = app;
