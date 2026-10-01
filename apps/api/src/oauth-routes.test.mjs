import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { registerOAuthRoutes } from "./oauth-routes";

describe("OAuth 2.0 and MCP Discovery Routes", () => {
  const createApp = (overrides = {}) => {
    const app = new Hono();
    registerOAuthRoutes(app, {
      getAdminUser: async () => ({
        id: "usr_admin",
        username: "admin",
        workspaceId: "ws_default",
      }),
      createApiToken: async () => "eev_test_token_12345",
      ...overrides,
    });
    return app;
  };

  test("returns RFC 8414 OAuth authorization server metadata", async () => {
    const app = createApp();
    const res = await app.request("https://notes.soninewmedia.com/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.issuer).toBe("https://notes.soninewmedia.com");
    expect(body.authorization_endpoint).toBe("https://notes.soninewmedia.com/oauth/authorize");
    expect(body.token_endpoint).toBe("https://notes.soninewmedia.com/oauth/token");
    expect(body.response_types_supported).toContain("code");
    expect(body.grant_types_supported).toContain("authorization_code");
    expect(body.token_endpoint_auth_methods_supported).toContain("client_secret_post");
    expect(body.token_endpoint_auth_methods_supported).toContain("client_secret_basic");
  });

  test("handles authorization request with redirect URI and state", async () => {
    const app = createApp();
    const redirectUri = "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-113165181329655550316-notes_soninewmedia_com";
    const res = await app.request(
      `/oauth/authorize?response_type=code&client_id=gemini-spark&redirect_uri=${encodeURIComponent(redirectUri)}&state=test_state_123`
    );
    expect(res.status).toBe(302);
    const location = res.headers.get("Location");
    expect(location).toBeDefined();
    const url = new URL(location);
    expect(url.origin + url.pathname).toBe(redirectUri);
    expect(url.searchParams.get("state")).toBe("test_state_123");
    expect(url.searchParams.get("code")).toBeTruthy();
  });

  test("exchanges authorization code for access token via client_secret_post", async () => {
    const app = createApp();
    const redirectUri = "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-113165181329655550316-notes_soninewmedia_com";

    // 1. Get code
    const authRes = await app.request(
      `/oauth/authorize?response_type=code&client_id=gemini-spark&redirect_uri=${encodeURIComponent(redirectUri)}&state=xyz`
    );
    const code = new URL(authRes.headers.get("Location")).searchParams.get("code");

    // 2. Exchange code
    const tokenRes = await app.request("/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: "gemini-spark",
        client_secret: "gemini-secret",
      }).toString(),
    });

    expect(tokenRes.status).toBe(200);
    const body = await tokenRes.json();
    expect(body.access_token).toBe("eev_test_token_12345");
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeGreaterThan(0);
  });
});
