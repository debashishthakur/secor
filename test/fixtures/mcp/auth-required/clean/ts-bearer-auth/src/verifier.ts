import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";

export const verifier: OAuthTokenVerifier = {
  async verifyAccessToken(token: string) {
    const res = await fetch("https://auth.example.com/introspect", { method: "POST", body: new URLSearchParams({ token }) });
    const info = (await res.json()) as { client_id: string; scope: string; exp: number };
    return { token, clientId: info.client_id, scopes: info.scope.split(" "), expiresAt: info.exp };
  },
};
