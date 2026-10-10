import Anthropic from "@anthropic-ai/sdk";

export const claude = new Anthropic({ apiKey: process.env.NEXT_PUBLIC_ANTHROPIC_KEY, dangerouslyAllowBrowser: true });
