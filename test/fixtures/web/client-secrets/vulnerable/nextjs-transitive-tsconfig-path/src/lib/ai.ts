import { format } from "./format";

const OPENAI_KEY = "__FAKE_OPENAI__";

export async function ask(q: string) {
  return fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: { Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({ input: format(q) }),
  });
}
