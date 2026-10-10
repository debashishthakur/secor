import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const tokenTtlSeconds = 3600;
export const passwordField = "password";
export { openai, tokenTtlSeconds };
