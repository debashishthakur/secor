const { Router } = require("express");

const router = Router();
router.get("/shared/:token", (req, res) => res.json({ token: req.params.token }));
router.use(authenticate);
router.get("/:id", (req, res) => res.json({ id: req.params.id }));

module.exports = router;
