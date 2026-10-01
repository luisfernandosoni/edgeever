import type { Hono } from "hono";
import type { AppContext, AppEnv } from "./api-context";
import { randomToken } from "./auth-crypto";

export type AdminUser = {
  id: string;
  username: string;
  workspaceId: string;
};

export type OAuthRouteDependencies = {
  getAdminUser: (context: AppContext) => Promise<AdminUser | null>;
  createApiToken: (context: AppContext, user: AdminUser, label: string) => Promise<string>;
};

type StoredAuthCode = {
  clientId: string;
  redirectUri: string;
  state?: string;
  expiresAt: number;
};

// In-memory code store for local testing
const authCodes = new Map<string, StoredAuthCode>();

// Self-contained signed authorization code helpers for serverless/multi-worker execution
const OAUTH_CODE_SALT = "edgeever-oauth-code-signing-salt-2026";

const bytesToHex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

const encodeAuthCode = async (data: StoredAuthCode): Promise<string> => {
  const json = JSON.stringify(data);
  const dataBytes = new TextEncoder().encode(json);
  let binary = "";
  for (const byte of dataBytes) {
    binary += String.fromCharCode(byte);
  }
  const payload = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  
  // Sign with SHA-256 (32-character hex)
  const toSign = new TextEncoder().encode(`${payload}.${OAUTH_CODE_SALT}`);
  const digest = await crypto.subtle.digest("SHA-256", toSign);
  const signature = bytesToHex(new Uint8Array(digest)).slice(0, 32);
  
  return `code_${payload}.${signature}`;
};

const decodeAuthCode = async (code: string): Promise<StoredAuthCode | null> => {
  if (authCodes.has(code)) {
    const mem = authCodes.get(code)!;
    if (mem.expiresAt >= Date.now()) {
      return mem;
    }
  }

  if (!code.startsWith("code_")) return null;
  const dotIndex = code.lastIndexOf(".");
  if (dotIndex === -1) return null;
  const payload = code.slice(5, dotIndex);
  const signature = code.slice(dotIndex + 1);

  // Verify signature
  const toSign = new TextEncoder().encode(`${payload}.${OAUTH_CODE_SALT}`);
  const digest = await crypto.subtle.digest("SHA-256", toSign);
  const expectedSig = bytesToHex(new Uint8Array(digest)).slice(0, 32);

  if (signature !== expectedSig) return null;

  try {
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const json = new TextDecoder().decode(bytes);
    const data = JSON.parse(json) as StoredAuthCode;
    if (data.expiresAt < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
};

export const registerOAuthRoutes = (
  app: Hono<AppEnv>,
  dependencies: OAuthRouteDependencies,
) => {
  // RFC 8414 & OpenID Connect Discovery
  const handleDiscovery = (c: AppContext) => {
    const origin = new URL(c.req.url).origin;
    return c.json({
      issuer: origin,
      authorization_endpoint: `${origin}/oauth/authorize`,
      token_endpoint: `${origin}/oauth/token`,
      registration_endpoint: `${origin}/oauth/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256", "plain"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      scopes_supported: ["read:memos", "write:memos", "read:notebooks", "write:notebooks", "read:resources"],
    });
  };

  app.get("/.well-known/oauth-authorization-server", handleDiscovery);
  app.get("/.well-known/openid-configuration", handleDiscovery);

  // RFC 9728 Protected Resource Metadata for MCP
  app.get("/.well-known/oauth-protected-resource", (c) => {
    const origin = new URL(c.req.url).origin;
    return c.json({
      resource: `${origin}/mcp`,
      authorization_servers: [origin],
      scopes_supported: ["read:memos", "write:memos", "read:notebooks", "write:notebooks", "read:resources"],
      bearer_methods_supported: ["header"],
    });
  });

  // GET /oauth/authorize
  app.get("/oauth/authorize", async (c) => {
    const clientId = c.req.query("client_id") || "gemini-spark";
    const redirectUri = c.req.query("redirect_uri");
    const state = c.req.query("state");

    if (!redirectUri) {
      return c.text("Missing redirect_uri parameter", 400);
    }

    // Auto-approve and generate authorization code
    const stored: StoredAuthCode = {
      clientId,
      redirectUri,
      state: state || undefined,
      expiresAt: Date.now() + 10 * 60 * 1000,
    };
    const code = await encodeAuthCode(stored);
    authCodes.set(code, stored);

    const target = new URL(redirectUri);
    target.searchParams.set("code", code);
    if (state) {
      target.searchParams.set("state", state);
    }

    return c.redirect(target.toString(), 302);
  });

  // POST /oauth/token
  app.post("/oauth/token", async (c) => {
    let grantType: string | undefined;
    let code: string | undefined;
    let redirectUri: string | undefined;
    let clientId: string | undefined;

    const contentType = c.req.header("Content-Type") || "";
    if (contentType.includes("application/x-www-form-urlencoded")) {
      const body = await c.req.parseBody();
      grantType = body.grant_type as string;
      code = body.code as string;
      redirectUri = body.redirect_uri as string;
      clientId = body.client_id as string;
    } else {
      const body = await c.req.json().catch(() => ({}));
      grantType = body.grant_type;
      code = body.code;
      redirectUri = body.redirect_uri;
      clientId = body.client_id;
    }

    // Also support Basic auth for client_id
    const authHeader = c.req.header("Authorization");
    if (authHeader && authHeader.startsWith("Basic ")) {
      try {
        const decoded = atob(authHeader.slice(6));
        const [id] = decoded.split(":");
        clientId = clientId || id;
      } catch {}
    }

    if (grantType !== "authorization_code") {
      return c.json({ error: "unsupported_grant_type" }, 400);
    }

    if (!code) {
      return c.json({ error: "invalid_request", error_description: "Missing code" }, 400);
    }

    const record = await decodeAuthCode(code);
    if (!record || record.expiresAt < Date.now()) {
      return c.json({ error: "invalid_grant", error_description: "Code expired or invalid" }, 400);
    }

    // Invalidate single-use code from memory
    authCodes.delete(code);

    const admin = await dependencies.getAdminUser(c);
    if (!admin) {
      return c.json({ error: "server_error", error_description: "Admin user not available" }, 500);
    }

    const token = await dependencies.createApiToken(c, admin, `OAuth: ${clientId || "Gemini Spark"}`);

    return c.json({
      access_token: token,
      token_type: "Bearer",
      expires_in: 365 * 24 * 3600, // 1 year
      scope: "read:memos write:memos read:notebooks write:notebooks read:resources",
    });
  });
};
