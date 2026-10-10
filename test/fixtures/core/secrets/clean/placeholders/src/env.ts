// Placeholders and environment lookups are not secrets.
export const config = {
  openaiKey: "sk-your-openai-key-goes-here-000000",
  apiSecret: "${OPENAI_API_SECRET_VALUE}",
  token: process.env.API_TOKEN,
  clientSecret: "<insert-client-secret-here>",
  accessKey: "changeme-changeme-changeme",
  privateKey: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  sessionSecret: import.meta.env.SESSION_SECRET,
};
