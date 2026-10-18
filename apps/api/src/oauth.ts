import { createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";

// §7.3: the gateway is a protected resource, not an identity provider. It
// validates the access token it is handed - signature against the issuer's
// published keys, issuer, canonical audience/resource, and expiry - and maps
// the validated subject and scopes to a principal. Self-reported metadata is
// never identity. Implemented on node:crypto so there is no JWT dependency to
// keep patched; the algorithms below are the only ones accepted.

export interface OAuthConfig {
  issuer: string;
  audience: string;
  jwksFile?: string;
  jwksUrl?: string;
  algorithms?: string[];
  clockSkewSeconds?: number;
}

export interface OAuthClaims {
  sub: string;
  scopes: string[];
  workspaces: string[];
}

interface Jwk {
  kid?: string;
  kty?: string;
  crv?: string;
  use?: string;
  n?: string;
  e?: string;
  x?: string;
  y?: string;
}

const DEFAULT_ALGORITHMS = ["EdDSA", "RS256", "ES256"];
const DEFAULT_SKEW_SECONDS = 30;
// A rotated-in key must be picked up promptly when a token names a kid we
// have not seen, but an attacker naming garbage kids must not turn every
// request into an outbound fetch.
const REFRESH_MIN_INTERVAL_MS = 10_000;
const FETCH_TIMEOUT_MS = 5_000;

export function oauthConfigFromEnv(env: NodeJS.ProcessEnv = process.env): OAuthConfig | null {
  const issuer = env.OAUTH_ISSUER?.trim();
  const audience = env.OAUTH_AUDIENCE?.trim();
  const jwksFile = env.OAUTH_JWKS_FILE?.trim();
  const jwksUrl = env.OAUTH_JWKS_URL?.trim();
  // Half-configured OAuth is a misconfiguration, not a fallback: the caller
  // decides what to do about it (see assertProductionAuth).
  if (!issuer || !audience || (!jwksFile && !jwksUrl)) return null;
  return {
    issuer,
    audience,
    jwksFile: jwksFile || undefined,
    jwksUrl: jwksUrl || undefined
  };
}

// §7.3: production runs on OAuth tokens. Static bearer keys are the explicit
// development profile, so a production start without an issuer refuses to
// come up rather than silently accepting development keys.
export function assertProductionAuth(env: NodeJS.ProcessEnv = process.env): void {
  if (env.NODE_ENV !== "production") return;
  if (!oauthConfigFromEnv(env)) {
    throw new Error(
      "NODE_ENV=production with only static bearer keys: set OAUTH_ISSUER, OAUTH_AUDIENCE and OAUTH_JWKS_FILE or OAUTH_JWKS_URL (§7.3)"
    );
  }
}

interface CachedKeys {
  keys: Map<string, KeyObject>;
  fetchedAt: number;
}

const keyCache = new Map<string, CachedKeys>();

function sourceOf(cfg: OAuthConfig): string {
  return (cfg.jwksUrl ?? cfg.jwksFile ?? "").trim();
}

async function loadJwks(source: string, cfg: OAuthConfig): Promise<Map<string, KeyObject>> {
  let body: string;
  if (cfg.jwksUrl) {
    const res = await fetch(cfg.jwksUrl, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
    body = await res.text();
  } else {
    body = readFileSync(cfg.jwksFile as string, "utf8");
  }
  const parsed = JSON.parse(body) as { keys?: Jwk[] };
  const keys = new Map<string, KeyObject>();
  for (const jwk of parsed.keys ?? []) {
    if (!jwk.kid) continue;
    keys.set(jwk.kid, createPublicKey({ key: jwk as never, format: "jwk" }));
  }
  keyCache.set(source, { keys, fetchedAt: Date.now() });
  return keys;
}

async function keyFor(cfg: OAuthConfig, kid: string): Promise<KeyObject | null> {
  const source = sourceOf(cfg);
  const cached = keyCache.get(source);
  if (cached && cached.keys.has(kid)) return cached.keys.get(kid) as KeyObject;
  if (cached && Date.now() - cached.fetchedAt < REFRESH_MIN_INTERVAL_MS) return null;
  // Unknown kid (or a cold cache): reload once and look again, so issuer key
  // rotation does not require a gateway restart.
  const keys = await loadJwks(source, cfg);
  return keys.get(kid) ?? null;
}

function signatureAlgorithm(alg: string): { name: string | null; p1363: boolean } | null {
  switch (alg) {
    case "EdDSA":
      return { name: null, p1363: false };
    case "RS256":
      return { name: "RSA-SHA256", p1363: false };
    case "ES256":
      // JOSE carries ECDSA signatures as raw r||s, not DER.
      return { name: "sha256", p1363: true };
    default:
      return null;
  }
}

function jsonPart<T>(part: string): T {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as T;
}

function claimAudience(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  return [];
}

function claimScopes(payload: Record<string, unknown>): string[] {
  const scope = payload.scope;
  if (typeof scope === "string") return scope.split(/\s+/).filter(Boolean);
  const scp = payload.scp;
  if (typeof scp === "string") return scp.split(/\s+/).filter(Boolean);
  if (Array.isArray(scp)) return scp.filter((v): v is string => typeof v === "string");
  return [];
}

export class OAuthError extends Error {}

function fail(reason: string): never {
  throw new OAuthError(reason);
}

// Validates one access token. Throws OAuthError with a stable reason on every
// failure; the caller decides whether the reason is echoed (it is logged, not
// returned to the agent). `nowMs` exists so expiry tests do not sleep.
export async function verifyAccessToken(
  token: string,
  cfg: OAuthConfig,
  nowMs = Date.now()
): Promise<OAuthClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) fail("malformed");
  const [rawHeader, rawPayload, rawSignature] = parts as [string, string, string];

  let header: { alg?: string; kid?: string; typ?: string };
  let payload: Record<string, unknown>;
  try {
    header = jsonPart(rawHeader);
    payload = jsonPart(rawPayload);
  } catch {
    fail("malformed");
  }

  const algorithms = cfg.algorithms ?? DEFAULT_ALGORITHMS;
  if (typeof header.alg !== "string" || !algorithms.includes(header.alg)) {
    fail(`algorithm ${header.alg ?? "(none)"} not accepted`);
  }
  const sig = signatureAlgorithm(header.alg);
  if (!sig) fail(`algorithm ${header.alg} not implemented`);

  if (typeof header.kid !== "string" || !header.kid) fail("missing kid");
  const key = await keyFor(cfg, header.kid);
  if (!key) fail(`no trusted key for kid ${header.kid}`);

  const signed = Buffer.from(`${rawHeader}.${rawPayload}`);
  const signature = Buffer.from(rawSignature, "base64url");
  let ok = false;
  try {
    ok = sig.p1363
      ? cryptoVerify("sha256", signed, { key, dsaEncoding: "ieee-p1363" }, signature)
      : sig.name === null
        ? cryptoVerify(null, signed, key, signature)
        : cryptoVerify(sig.name, signed, key, signature);
  } catch {
    // A key that does not match the declared algorithm throws instead of
    // returning false; both mean the same thing here.
    ok = false;
  }
  if (!ok) fail("signature does not verify");

  if (payload.iss !== cfg.issuer) fail("wrong issuer");
  if (!claimAudience(payload.aud).includes(cfg.audience)) fail("wrong audience");
  if (typeof payload.exp !== "number") fail("missing exp");
  const skew = (cfg.clockSkewSeconds ?? DEFAULT_SKEW_SECONDS) * 1000;
  if (payload.exp * 1000 + skew < nowMs) fail("expired");
  if (typeof payload.nbf === "number" && payload.nbf * 1000 - skew > nowMs) fail("not yet valid");
  if (typeof payload.sub !== "string" || !payload.sub) fail("missing sub");

  const workspaces = Array.isArray(payload.workspaces)
    ? payload.workspaces.filter((w): w is string => typeof w === "string")
    : [];
  return { sub: payload.sub, scopes: claimScopes(payload), workspaces };
}

// RFC 9728: what the gateway tells a client about how to get a token for it.
// The origin of the canonical audience/resource is where the document lives.
export function protectedResourceMetadata(cfg: OAuthConfig): Record<string, unknown> {
  return {
    resource: cfg.audience,
    authorization_servers: [cfg.issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: ["gateway", "approve", "read", "ingest", "admin"]
  };
}

export function resourceMetadataUrl(cfg: OAuthConfig): string {
  try {
    return `${new URL(cfg.audience).origin}/.well-known/oauth-protected-resource`;
  } catch {
    return "/.well-known/oauth-protected-resource";
  }
}
