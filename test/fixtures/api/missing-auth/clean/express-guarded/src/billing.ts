import { Router } from "express";

const router = Router();
router.get("/invoices", (req, res) => res.json([]));

export default router;
