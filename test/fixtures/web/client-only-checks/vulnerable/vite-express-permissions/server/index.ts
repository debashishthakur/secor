import express from "express";
import { requireAuth } from "./auth";

const app = express();

app.delete("/api/posts/:id", requireAuth, async (req, res) => {
  await removeFromDb(req.params.id);
  res.sendStatus(204);
});

async function removeFromDb(_id: string) {
  return null;
}

app.listen(3000);
