import { createHash, randomBytes } from "node:crypto";
import { ShimError } from "./errors.js";

// The client half of FR-002 (§7.3). Headless agents use client_credentials;
// interactive or user-delegated clients use Authorization Code + PKCE. Both
// flows use the RFC 8707 resource indicator. The shim:
//
//   1. discovers the gateway's protected-resource metadata (RFC 9728),
//   2. discovers the authorization server's metadata (RFC 8414) and checks
//      the issuer binding in both directions,
//   3. asks for a token scoped to the resource it is about to call,
//   4. caches it until shortly before expiry, refreshing on a 401 once.
//
// The token is sent to the gateway and nowhere else: the authorization
// server sees only the client credentials or the one-time authorization
// code, never the access token.

export class OAuthClientError extends ShimError {
  constructor(message: string, code = "OAUTH_CLIENT_ERROR") {
    super(message, code);
  }
}

export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers?: string[];
  scopes_supported?: string[];
}

export interface AuthorizationServerMetadata {
  issuer: string;
  token_endpoint: string;
  authorization_endpoint?: string;
  grant_types_supported?: string[];
  code_challenge_methods_supported?: string[];
}

export interface AuthorizationCodeGrant {
  /** The one-time code returned to the redirect URI. */
  code: string;
  redirectUri: string;
  /** The RFC 7636 verifier whose S256 challenge began the flow. */
  codeVerifier: string;
}

export interface OAuthClientOptions {
  /** The canonical resource the shim calls; must equal the gateway's audience. */
  resource: string;
  clientId: string;
  clientSecret?: string;
  scopes?: string[];
  /** Expected issuer. Without it, the protected-resource metadata decides. */
  issuer?: string;
  /**
   * Interactive/user-delegated flow. When present the token request exchanges
   * this one-time code with PKCE instead of using client_credentials.
   */
  authorizationCode?: AuthorizationCodeGrant;
  fetchImpl?: typeof fetch;
  /** Test hook: the clock the token cache reads. */
  nowMs?: () => number;
}

export interface AuthorizationRequest {
  url: string;
  state: string;
  redirectUri: string;
  codeVerifier: string;
  codeChallenge: string;
}

const SKEW_MS = 30_000;
const normalize = (value: string) => value.replace(/\/+$/, "");
const PKCE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;

function wellKnown(base: string, path: string): URL {
  const url = new URL(base);
  return new URL(path, url);
}

export async function discoverProtectedResource(
  resource: string,
  fetchImpl: typeof fetch
): Promise<ProtectedResourceMetadata> {
  // RFC 9728 §3.1: a resource with a path publishes its metadata at the
  // path-appended location. Clients must try that one first; deployments
  // that only serve the bare document keep working through the fallback.
  const resourceUrl = new URL(resource);
  const candidates: URL[] = [];
  const path = resourceUrl.pathname.replace(/\/+$/, "");
  if (path) {
    candidates.push(new URL(`/.well-known/oauth-protected-resource${path}`, resourceUrl));
  }
  candidates.push(new URL("/.well-known/oauth-protected-resource", resourceUrl));

  let lastStatus = 0;
  for (const candidate of candidates) {
    const res = await fetchImpl(candidate, { headers: { accept: "application/json" } });
    if (!res.ok) {
      lastStatus = res.status;
      if (res.status !== 404) break;
      continue;
    }
    const metadata = (await res.json()) as ProtectedResourceMetadata;
    if (typeof metadata.resource !== "string") {
      throw new OAuthClientError("protected-resource metadata names no resource");
    }
    return metadata;
  }
  throw new OAuthClientError(
    `protected-resource metadata is unavailable (HTTP ${lastStatus})`,
    "OAUTH_METADATA_UNAVAILABLE"
  );
}

export async function discoverAuthorizationServer(
  issuer: string,
  fetchImpl: typeof fetch
): Promise<AuthorizationServerMetadata> {
  const res = await fetchImpl(wellKnown(issuer, "/.well-known/oauth-authorization-server"), {
    headers: { accept: "application/json" }
  });
  if (!res.ok) {
    throw new OAuthClientError(
      `authorization-server metadata is unavailable (HTTP ${res.status})`,
      "OAUTH_METADATA_UNAVAILABLE"
    );
  }
  const metadata = (await res.json()) as AuthorizationServerMetadata;
  // Issuer binding, both directions: the document at the issuer's well-known
  // location must name that same issuer, and it must be the one the resource
  // advertised. Anything else is a token issuer the gateway will not accept.
  if (typeof metadata.issuer !== "string" || normalize(metadata.issuer) !== normalize(issuer)) {
    throw new OAuthClientError(
      `authorization-server metadata names issuer "${metadata.issuer}" instead of "${issuer}"`,
      "OAUTH_ISSUER_MISMATCH"
    );
  }
  if (typeof metadata.token_endpoint !== "string") {
    throw new OAuthClientError("authorization-server metadata names no token endpoint");
  }
  return metadata;
}

// Both flows resolve the gateway's advertised issuer and then the issuer's
// metadata, with the same resource and issuer checks. Keeping that in one
// place means the interactive flow cannot accidentally skip them.
async function resolveServer(
  opts: Pick<OAuthClientOptions, "resource" | "issuer">,
  fetchImpl: typeof fetch
): Promise<{ server: AuthorizationServerMetadata; issuer: string }> {
  const advertised = await discoverProtectedResource(opts.resource, fetchImpl);
  if (normalize(advertised.resource) !== normalize(opts.resource)) {
    throw new OAuthClientError(
      `the gateway advertises resource "${advertised.resource}", not "${opts.resource}"`,
      "OAUTH_RESOURCE_MISMATCH"
    );
  }
  const issuer = opts.issuer ?? advertised.authorization_servers?.[0];
  if (!issuer) {
    throw new OAuthClientError("no authorization server is advertised for this resource");
  }
  if (
    opts.issuer &&
    advertised.authorization_servers?.length &&
    !advertised.authorization_servers.map(normalize).includes(normalize(opts.issuer))
  ) {
    throw new OAuthClientError(
      `the gateway does not accept tokens from issuer "${opts.issuer}"`,
      "OAUTH_ISSUER_MISMATCH"
    );
  }
  return { server: await discoverAuthorizationServer(issuer, fetchImpl), issuer };
}

/** Generates an RFC 7636 verifier and its S256 challenge. */
export function createPkcePair(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
  return { codeVerifier, codeChallenge };
}

/**
 * Discovers the issuer and builds the browser-facing authorization URL with
 * PKCE S256, state, resource, and scopes. Persist the returned verifier/state;
 * after the redirect, pass the returned code and verifier to OAuthClientOptions
 * as `authorizationCode`.
 */
export async function beginAuthorization(
  opts: Pick<OAuthClientOptions, "resource" | "clientId" | "scopes" | "issuer" | "fetchImpl">,
  params: { redirectUri: string; state?: string }
): Promise<AuthorizationRequest> {
  if (!opts.resource || !opts.clientId) {
    throw new OAuthClientError("OAuth needs both a resource and a client id");
  }
  const fetchImpl = opts.fetchImpl ?? fetch;
  const { server } = await resolveServer(opts, fetchImpl);
  if (!server.authorization_endpoint) {
    throw new OAuthClientError("authorization-server metadata names no authorization endpoint");
  }
  if (server.code_challenge_methods_supported && !server.code_challenge_methods_supported.includes("S256")) {
    throw new OAuthClientError(
      "authorization server does not advertise PKCE S256",
      "OAUTH_PKCE_UNAVAILABLE"
    );
  }
  const { codeVerifier, codeChallenge } = createPkcePair();
  const state = params.state ?? randomBytes(16).toString("base64url");
  const url = new URL(server.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", opts.clientId);
  url.searchParams.set("redirect_uri", params.redirectUri);
  if (opts.scopes?.length) url.searchParams.set("scope", opts.scopes.join(" "));
  url.searchParams.set("resource", opts.resource);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return { url: url.toString(), state, redirectUri: params.redirectUri, codeVerifier, codeChallenge };
}

interface CachedToken {
  value: string;
  expiresAt: number;
}

export class OAuthTokenSource {
  private readonly opts: OAuthClientOptions;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private cached?: CachedToken;
  private inFlight?: Promise<CachedToken>;
  private refreshToken?: string;
  private codeExchanged = false;

  constructor(opts: OAuthClientOptions) {
    if (!opts.resource || !opts.clientId) {
      throw new OAuthClientError("OAuth needs both a resource and a client id");
    }
    if (opts.authorizationCode) {
      if (!opts.authorizationCode.code || !opts.authorizationCode.redirectUri) {
        throw new OAuthClientError("Authorization Code needs both a code and a redirect URI");
      }
      if (
        typeof opts.authorizationCode.codeVerifier !== "string" ||
        !PKCE_VERIFIER.test(opts.authorizationCode.codeVerifier)
      ) {
        throw new OAuthClientError(
          "PKCE code verifier must be 43-128 characters from the RFC 7636 set",
          "OAUTH_PKCE_INVALID"
        );
      }
    }
    this.opts = opts;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.now = opts.nowMs ?? Date.now;
  }

  /** The token to present to the gateway, fetching or refreshing as needed. */
  async token(): Promise<string> {
    if (this.cached && this.cached.expiresAt - SKEW_MS > this.now()) {
      return this.cached.value;
    }
    return (await this.fetchToken()).value;
  }

  /** Drops the cache after a 401, so the next call fetches a fresh token. */
  invalidate(): void {
    this.cached = undefined;
  }

  private fetchToken(): Promise<CachedToken> {
    // Concurrent calls share one token request.
    this.inFlight ??= this.requestToken().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  private async requestToken(): Promise<CachedToken> {
    const { server, issuer } = await resolveServer(this.opts, this.fetchImpl);

    // RFC 8707: the token is minted for the resource we are about to call, so
    // a token for another service cannot be replayed here.
    const body = new URLSearchParams({ resource: this.opts.resource });
    const grant = this.opts.authorizationCode;
    if (grant) {
      if (this.refreshToken) {
        body.set("grant_type", "refresh_token");
        body.set("refresh_token", this.refreshToken);
      } else if (this.codeExchanged) {
        throw new OAuthClientError(
          "the authorization grant has no refresh token; restart the PKCE flow",
          "OAUTH_REAUTH_REQUIRED"
        );
      } else {
        body.set("grant_type", "authorization_code");
        body.set("code", grant.code);
        body.set("redirect_uri", grant.redirectUri);
        body.set("code_verifier", grant.codeVerifier);
      }
    } else {
      body.set("grant_type", "client_credentials");
    }
    // The authorization request already binds the scopes to the code.
    if (!grant && this.opts.scopes?.length) body.set("scope", this.opts.scopes.join(" "));

    const headers: Record<string, string> = {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json"
    };
    if (this.opts.clientSecret) {
      headers.authorization =
        `Basic ${Buffer.from(`${this.opts.clientId}:${this.opts.clientSecret}`).toString("base64")}`;
    } else {
      body.set("client_id", this.opts.clientId);
    }

    const res = await this.fetchImpl(server.token_endpoint, { method: "POST", headers, body });
    if (!res.ok) {
      throw new OAuthClientError(
        `token endpoint refused the client (HTTP ${res.status})`,
        "OAUTH_TOKEN_REFUSED"
      );
    }
    const payload = (await res.json()) as {
      access_token?: string; token_type?: string; expires_in?: number; iss?: string; refresh_token?: string;
    };
    if (typeof payload.access_token !== "string" || !payload.access_token) {
      throw new OAuthClientError("token endpoint returned no access token");
    }
    if (payload.token_type && payload.token_type.toLowerCase() !== "bearer") {
      throw new OAuthClientError(`token endpoint returned type "${payload.token_type}"`);
    }
    // RFC 9207: when the issuer stamps the response, it must be the issuer
    // this flow already decided to trust — a mismatch means a confused deputy.
    if (typeof payload.iss === "string" && normalize(payload.iss) !== normalize(issuer)) {
      throw new OAuthClientError(
        `token endpoint minted the token for issuer "${payload.iss}" instead of "${issuer}"`,
        "OAUTH_ISSUER_MISMATCH"
      );
    }
    if (grant) {
      this.codeExchanged = true;
      if (typeof payload.refresh_token === "string" && payload.refresh_token) {
        this.refreshToken = payload.refresh_token;
      }
    }
    const lifetimeMs =
      (typeof payload.expires_in === "number" && payload.expires_in > 0 ? payload.expires_in : 300) * 1000;
    this.cached = { value: payload.access_token, expiresAt: this.now() + lifetimeMs };
    return this.cached;
  }
}
