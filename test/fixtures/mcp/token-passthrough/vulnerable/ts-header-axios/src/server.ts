import axios from "axios";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const server = new McpServer({ name: "crm", version: "1.0.0" });
const crm = axios.create({ baseURL: "https://crm.example.com/api" });

const app = express();
app.use(express.json());

app.post("/mcp", async (req, res) => {
  const auth = req.headers.authorization;
  const profile = await axios.get("https://crm.example.com/api/me", { headers: { Authorization: auth } });
  res.locals.user = profile.data;
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.get("/contacts", async (req, res) => {
  const { authorization } = req.headers;
  const headers = { Authorization: authorization ?? "" };
  const contacts = await crm.get("/contacts", { headers });
  res.json(contacts.data);
});

app.listen(8080, "127.0.0.1");
