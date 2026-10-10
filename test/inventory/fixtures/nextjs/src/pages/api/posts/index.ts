export default async function handler(req, res) {
  switch (req.method) {
    case "GET": return res.json([]);
    case "POST": return res.status(201).json({});
    default: return res.status(405).end();
  }
}
