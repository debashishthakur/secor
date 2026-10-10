import { Router } from "express";
const router = Router();
router.get("/", async (req, res) => res.json([]));
router.get("/:id", async (req, res) => res.json({ id: req.params.id }));
router.put("/:id", isAuthenticated, async (req, res) => res.json({}));
function isAuthenticated(req: any, res: any, next: any) { next(); }
export default router;
