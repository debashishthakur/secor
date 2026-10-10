import "server-only";

const OPENAI_KEY = "__FAKE_OPENAI__";

export async function load() {
  return OPENAI_KEY.length;
}
