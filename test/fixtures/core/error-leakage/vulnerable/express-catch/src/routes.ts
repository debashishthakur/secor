import express from "express";

const router = express.Router();

router.get("/users/:id", async (req, res) => {
  try {
    res.json(await findUser(req.params.id));
  } catch (e) {
    res.status(500).send(e);
  }
});

router.post("/orders", async (req, res) => {
  try {
    res.json(await createOrder(req.body));
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

router.get("/report", (req, res) => {
  buildReport()
    .then((r) => res.json(r))
    .catch((error) => res.status(500).json({ error: error.toString() }));
});

export default router;
