const express = require("express");
const { randomUUID } = require("node:crypto");

const app = express();
const router = express.Router();

router.get("/x", async (req, res) => {
  try {
    res.json(await work());
  } catch (e) {
    const id = randomUUID();
    console.error(id, e);
    res.status(500).json({ error: "Internal error", id });
  }
});

app.use("/api", router);

// Only the message reaches the caller.
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: err.message });
});

// express-generator style: the error object only in development.
app.use(function (err, req, res, next) {
  res.status(err.status || 500);
  res.json({ message: err.message, error: req.app.get("env") === "development" ? err : {} });
});

if (process.env.NODE_ENV !== "production") {
  app.use((err, req, res, next) => res.status(500).send(err.stack));
}

// Writing to stderr is logging, not a response.
process.on("uncaughtException", (err) => {
  process.stderr.write(err.stack);
});

module.exports = app;
