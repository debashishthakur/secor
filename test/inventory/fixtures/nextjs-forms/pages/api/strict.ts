export default function handler(req, res) {
  if (req.method === "PUT") return res.json({});
  res.setHeader("Allow", "PUT");
  res.status(405).end();
}
