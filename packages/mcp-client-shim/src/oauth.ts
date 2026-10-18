import { ShimError } from "./errors.js";

// The client half of FR-002 (§7.3). A headless agent has no browser, so the
// flow is client_credentials with the RFC 8707 resource indicator; the
// discovery and issuer-binding code here is what an interactive client would
// reuse when Authorization Code + PKCE lands. The shim:
//
//   1. discovers the gateway's protected-resource metadata (RFC 9728),
//   2. discovers the authorization server's metadata (RFC 8414) and checks
//      the issuer binding in both directions,
//   3. asks for a token scoped to the resource it is about to call,
//   4. caches it until shortly before expiry, refreshing on a 401 once.
//
// The token is sent to the gateway and nowhere else: the authorization
// server sees only the client credentials, never the access token.

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
  grant_types_supported?: string[];
}

export interface OAuthClientOptions {
  /** The canonical resource the shim calls; must equal the gateway's audience. */
  resource: string;
  clientId: string;
  clientSecret?: string;
  scopes?: string[];
  /** Expected issuer. Without it, the protected-resource metadata decides. */
  issuer?: string;
  fetchImpl?: typeof fetch;
  /** Test hook: the clock the token cache reads. */
  nowMs?: () => number;
}

const SKEW_MS = 30_000;

function wellKnown(base: string, path: string): URL {
  const url = new URL(base);
  return new URL(path, url);
}

export async function discoverProtectedResource(
  resource: string,
  fetchImpl: typeof fetch
): Promise<ProtectedResourceMetadata> {
  const res = await fetchImpl(wellKnown(resource, "/.well-known/oauth-protected-resource"), {
    headers: { accept: "application/json" }
  });
  if (!res.ok) {
    throw new OAuthClientError(
      `protected-resource metadata is unavailable (HTTP ${res.status})`,
      "OAUTH_METADATA_UNAVAILABLE"
    );
  }
  const metadata = (await res.json()) as ProtectedResourceMetadata;
  if (typeof metadata.resource !== "string") {
    throw new OAuthClientError("protected-resource metadata names no resource");
  }
  return metadata;
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
  const normalize = (value: string) => value.replace(/\/$/, "");
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

  constructor(opts: OAuthClientOptions) {
    if (!opts.resource || !opts.clientId) {
      throw new OAuthClientError("OAuth needs both a resource and a client id");
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
    const advertised = await discoverProtectedResource(this.opts.resource, this.fetchImpl);
    const normalize = (value: string) => value.replace(/\/$/, "");
    if (normalize(advertised.resource) !== normalize(this.opts.resource)) {
      throw new OAuthClientError(
        `the gateway advertises resource "${advertised.resource}", not "${this.opts.resource}"`,
        "OAUTH_RESOURCE_MISMATCH"
      );
    }
    const issuer = this.opts.issuer ?? advertised.authorization_servers?.[0];
    if (!issuer) {
      throw new OAuthClientError("no authorization server is advertised for this resource");
    }
    if (
      this.opts.issuer &&
      advertised.authorization_servers?.length &&
      !advertised.authorization_servers.map(normalize).includes(normalize(this.opts.issuer))
    ) {
      throw new OAuthClientError(
        `the gateway does not accept tokens from issuer "${this.opts.issuer}"`,
        "OAUTH_ISSUER_MISMATCH"
      );
    }
    const server = await discoverAuthorizationServer(issuer, this.fetchImpl);

    const body = new URLSearchParams({
      grant_type: "client_credentials",
      // RFC 8707: the token is minted for the resource we are about to call,
      // so a token for another service cannot be replayed here.
      resource: this.opts.resource
    });
    if (this.opts.scopes?.length) body.set("scope", this.opts.scopes.join(" "));

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
      access_token?: string; token_type?: string; expires_in?: number;
    };
    if (typeof payload.access_token !== "string" || !payload.access_token) {
      throw new OAuthClientError("token endpoint returned no access token");
    }
    if (payload.token_type && payload.token_type.toLowerCase() !== "bearer") {
      throw new OAuthClientError(`token endpoint returned type "${payload.token_type}"`);
    }
    const lifetimeMs =
      (typeof payload.expires_in === "number" && payload.expires_in > 0 ? payload.expires_in : 300) * 1000;
    this.cached = { value: payload.access_token, expiresAt: this.now() + lifetimeMs };
    return this.cached;
  }
}
