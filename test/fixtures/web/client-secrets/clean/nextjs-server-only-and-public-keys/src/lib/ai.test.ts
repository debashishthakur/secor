import OpenAI from "openai";

// jsdom tests need the browser flag; test files are never shipped.
export const client = new OpenAI({ apiKey: "test", dangerouslyAllowBrowser: true });
