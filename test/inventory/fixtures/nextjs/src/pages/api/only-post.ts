export default function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();
  res.json({});
}
