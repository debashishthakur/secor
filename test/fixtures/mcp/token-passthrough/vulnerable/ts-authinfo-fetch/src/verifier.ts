import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";

export const verifier: OAuthTokenVerifier = {
  async verifyAccessToken(token: string) {
    return { token, clientId: "github-proxy", scopes: ["repo"] };
  },
};
