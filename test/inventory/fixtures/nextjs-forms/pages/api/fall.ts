export default function handler(req, res) {
  if (req.method === "POST") {
    return res.status(201).json({});
  }
  res.json({ list: [] });
}
