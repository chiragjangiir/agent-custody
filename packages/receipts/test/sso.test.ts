import { createHash, createHmac, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { SignedXml } from "xml-crypto";
import { describe, expect, it } from "vitest";
import { oidcAuthorizeUrl, oidcExchange, pkce, samlAuthorizeUrl, samlValidate, type OidcConfig } from "../src/sso.ts";

const b64 = (v: unknown) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");

const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const rsaOther = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const ec384 = generateKeyPairSync("ec", { namedCurve: "secp384r1" });
const jwk = (k: KeyObject, kid: string) => ({ ...k.export({ format: "jwk" }), kid, use: "sig" });

let n = 0;
// a new issuer per test, because the module caches per issuer
function idp(opts: { discoveryIssuer?: string; keys?: unknown[]; endpoints?: Record<string, string> } = {}) {
  const issuer = `https://idp${++n}.example.com`;
  const cfg: OidcConfig = { issuer, clientId: "client-1", clientSecret: "s3cret" };
  const calls: { url: string; body?: URLSearchParams }[] = [];
  const keys = opts.keys ?? [jwk(rsa.publicKey, "rs1"), jwk(ec.publicKey, "ec1")];
  let idToken = "";
  const fetch = (async (url: string, init?: RequestInit) => {
    calls.push({ url, ...(init?.body ? { body: init.body as URLSearchParams } : {}) });
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    const json = (v: unknown) => new Response(JSON.stringify(v), { headers: { "content-type": "application/json" } });
    if (url.endsWith("/.well-known/openid-configuration")) return json({ issuer: opts.discoveryIssuer ?? issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks`, ...opts.endpoints });
    if (url.endsWith("/jwks")) return json({ keys });
    if (url.endsWith("/token")) return json({ id_token: idToken });
    return new Response("nope", { status: 404 });
  }) as typeof globalThis.fetch;
  return { cfg, fetch, calls, keys, setToken: (t: string) => { idToken = t; } };
}

const now = Math.floor(Date.now() / 1000);
const goodClaims = (cfg: OidcConfig) => ({ iss: cfg.issuer, aud: cfg.clientId, sub: "u-1", email: "Alice@Acme.com", nonce: "n-1", iat: now, exp: now + 300 });
function jws(header: Record<string, unknown>, claims: unknown, alg: "RS256" | "ES256" | "HS256" | "none", key?: KeyObject | string): string {
  const input = `${b64(header)}.${b64(claims)}`;
  const sig = alg === "RS256" ? sign("sha256", Buffer.from(input), key as KeyObject)
    : alg === "ES256" ? sign("sha256", Buffer.from(input), { key: key as KeyObject, dsaEncoding: "ieee-p1363" })
    : alg === "HS256" ? createHmac("sha256", key as string).update(input).digest()
    : Buffer.from("x");
  return `${input}.${sig.toString("base64url")}`;
}

describe("OIDC", () => {
  it("builds an authorization-code URL with PKCE S256, state, and nonce", async () => {
    const { cfg, fetch } = idp();
    const { verifier, challenge } = pkce();
    const url = new URL(await oidcAuthorizeUrl(cfg, { redirectUri: "https://p.example/cb", state: "st", nonce: "n-1", codeChallenge: challenge, fetch }));
    expect(url.origin + url.pathname).toBe(`${cfg.issuer}/authorize`);
    expect(Object.fromEntries(url.searchParams)).toMatchObject({ response_type: "code", client_id: "client-1", scope: "openid email profile", state: "st", nonce: "n-1", code_challenge: challenge, code_challenge_method: "S256" });
    expect(challenge).toBe(createHash("sha256").update(verifier).digest("base64url"));
  });

  it.each([
    ["RS256", () => ({ alg: "RS256", kid: "rs1" }), rsa.privateKey],
    ["ES256", () => ({ alg: "ES256", kid: "ec1" }), ec.privateKey],
  ] as const)("accepts a good %s id_token and sends the code verifier and secret", async (alg, header, key) => {
    const p = idp();
    p.setToken(jws(header(), goodClaims(p.cfg), alg, key));
    const id = await oidcExchange(p.cfg, { code: "c", redirectUri: "https://p.example/cb", codeVerifier: "v", nonce: "n-1", fetch: p.fetch });
    expect(id).toEqual({ subject: "u-1", email: "alice@acme.com" });
    const body = p.calls.find((c) => c.url.endsWith("/token"))!.body!;
    expect(Object.fromEntries(body)).toMatchObject({ grant_type: "authorization_code", code: "c", code_verifier: "v", client_secret: "s3cret", client_id: "client-1" });
  });

  it("refetches the key set once for an unknown kid, then accepts the rotated key", async () => {
    const p = idp();
    p.setToken(jws({ alg: "RS256", kid: "rs1" }, goodClaims(p.cfg), "RS256", rsa.privateKey));
    await oidcExchange(p.cfg, { code: "c", redirectUri: "r", codeVerifier: "v", nonce: "n-1", fetch: p.fetch });
    p.keys.push(jwk(rsaOther.publicKey, "rs2"));
    p.setToken(jws({ alg: "RS256", kid: "rs2" }, goodClaims(p.cfg), "RS256", rsaOther.privateKey));
    await oidcExchange(p.cfg, { code: "c", redirectUri: "r", codeVerifier: "v", nonce: "n-1", fetch: p.fetch });
    expect(p.calls.filter((c) => c.url.endsWith("/jwks"))).toHaveLength(2);
    p.setToken(jws({ alg: "RS256", kid: "ghost" }, goodClaims(p.cfg), "RS256", rsaOther.privateKey));
    await expect(oidcExchange(p.cfg, { code: "c", redirectUri: "r", codeVerifier: "v", nonce: "n-1", fetch: p.fetch })).rejects.toThrow(/no key/);
    expect(p.calls.filter((c) => c.url.endsWith("/jwks"))).toHaveLength(3);
  });

  it("accepts an id_token with no email_verified claim", async () => {
    const p = idp();
    p.setToken(jws({ alg: "RS256", kid: "rs1" }, goodClaims(p.cfg), "RS256", rsa.privateKey));
    await expect(oidcExchange(p.cfg, { code: "c", redirectUri: "r", codeVerifier: "v", nonce: "n-1", fetch: p.fetch })).resolves.toMatchObject({ email: "alice@acme.com" });
  });

  const rsHeader = { alg: "RS256", kid: "rs1" };
  it.each([
    ["a signature from another key", /signature/, (c: OidcConfig) => jws(rsHeader, goodClaims(c), "RS256", rsaOther.privateKey)],
    ["alg none", /not accepted/, (c: OidcConfig) => jws({ alg: "none", kid: "rs1" }, goodClaims(c), "none")],
    ["HS256 keyed with the public key", /not accepted/, (c: OidcConfig) => jws({ alg: "HS256", kid: "rs1" }, goodClaims(c), "HS256", rsa.publicKey.export({ format: "pem", type: "spki" }) as string)],
    ["the wrong issuer", /issuer/, (c: OidcConfig) => jws(rsHeader, { ...goodClaims(c), iss: "https://evil.example.com" }, "RS256", rsa.privateKey)],
    ["the wrong audience", /audience/, (c: OidcConfig) => jws(rsHeader, { ...goodClaims(c), aud: "other-client" }, "RS256", rsa.privateKey)],
    ["several audiences and no azp", /azp/, (c: OidcConfig) => jws(rsHeader, { ...goodClaims(c), aud: ["client-1", "other"] }, "RS256", rsa.privateKey)],
    ["an expired token", /expired/, (c: OidcConfig) => jws(rsHeader, { ...goodClaims(c), exp: now - 3600 }, "RS256", rsa.privateKey)],
    ["the wrong nonce", /nonce/, (c: OidcConfig) => jws(rsHeader, { ...goodClaims(c), nonce: "replayed" }, "RS256", rsa.privateKey)],
    ["email_verified false", /not verified/, (c: OidcConfig) => jws(rsHeader, { ...goodClaims(c), email_verified: false }, "RS256", rsa.privateKey)],
    ["an id_token issued an hour ahead", /future/, (c: OidcConfig) => jws(rsHeader, { ...goodClaims(c), iat: now + 3600, exp: now + 7200 }, "RS256", rsa.privateKey)],
    ["no email", /email/, (c: OidcConfig) => jws(rsHeader, { ...goodClaims(c), email: undefined }, "RS256", rsa.privateKey)],
  ])("refuses %s", async (_name, error, make) => {
    const p = idp();
    p.setToken(make(p.cfg));
    await expect(oidcExchange(p.cfg, { code: "c", redirectUri: "r", codeVerifier: "v", nonce: "n-1", fetch: p.fetch })).rejects.toThrow(error);
  });

  it("refuses a token response that is not JSON with the HTTP status, not a parse error", async () => {
    const p = idp();
    const fetch = (async (url: string, init?: RequestInit) => url.endsWith("/token") ? new Response("<html>Bad Gateway</html>", { status: 502 }) : p.fetch(url, init)) as typeof globalThis.fetch;
    await expect(oidcExchange(p.cfg, { code: "c", redirectUri: "r", codeVerifier: "v", nonce: "n-1", fetch })).rejects.toThrow(/^the OIDC token endpoint refused the code \(HTTP 502\)$/);
  });

  it("refuses a key that is marked for encryption, even when its kid matches", async () => {
    const p = idp({ keys: [{ ...jwk(rsa.publicKey, "rs1"), use: "enc" }] });
    p.setToken(jws(rsHeader, goodClaims(p.cfg), "RS256", rsa.privateKey));
    await expect(oidcExchange(p.cfg, { code: "c", redirectUri: "r", codeVerifier: "v", nonce: "n-1", fetch: p.fetch })).rejects.toThrow(/no key/);
  });

  it("refuses an ES256 id_token whose key is not on the P-256 curve", async () => {
    const p = idp({ keys: [jwk(ec384.publicKey, "ec1")] });
    p.setToken(jws({ alg: "ES256", kid: "ec1" }, goodClaims(p.cfg), "ES256", ec384.privateKey));
    await expect(oidcExchange(p.cfg, { code: "c", redirectUri: "r", codeVerifier: "v", nonce: "n-1", fetch: p.fetch })).rejects.toThrow(/signature/);
  });

  it.each(["authorization_endpoint", "token_endpoint", "jwks_uri"])("refuses a discovery document whose %s is not https, so the client secret never goes out in clear", async (name) => {
    const plain = idp({ endpoints: { [name]: "http://idp.example.com/endpoint" } });
    await expect(oidcAuthorizeUrl(plain.cfg, { redirectUri: "r", state: "s", nonce: "n", codeChallenge: "c", fetch: plain.fetch })).rejects.toThrow(/must be an https URL/);
    plain.setToken(jws(rsHeader, goodClaims(plain.cfg), "RS256", rsa.privateKey));
    await expect(oidcExchange(plain.cfg, { code: "c", redirectUri: "r", codeVerifier: "v", nonce: "n-1", fetch: plain.fetch })).rejects.toThrow(/must be an https URL/);
    expect(plain.calls.some((c) => c.body)).toBe(false);
  });

  it("refuses an issuer that is not https, and a discovery document for another issuer", async () => {
    const plain = idp();
    await expect(oidcAuthorizeUrl({ ...plain.cfg, issuer: "http://idp.example.com" }, { redirectUri: "r", state: "s", nonce: "n", codeChallenge: "c", fetch: plain.fetch })).rejects.toThrow(/https/);
    expect(plain.calls).toHaveLength(0);
    const other = idp({ discoveryIssuer: "https://other.example.com" });
    await expect(oidcAuthorizeUrl(other.cfg, { redirectUri: "r", state: "s", nonce: "n", codeChallenge: "c", fetch: other.fetch })).rejects.toThrow(/different issuer/);
  });
});

const idpKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const idpPublicPem = idpKeys.publicKey.export({ format: "pem", type: "spki" }) as string;
const SP = { spEntityId: "https://portal.example.com/saml", acsUrl: "https://portal.example.com/auth/saml/acs" };
const CONFIG = { entryPoint: "https://idp.example.com/sso", idpCert: idpPublicPem, idpIssuer: "https://idp.example.com/meta" };
const REQUEST_ID = "_req123";
const iso = (ms: number) => new Date(Date.now() + ms).toISOString();

interface Opts { recipient?: string; scNotOnOrAfter?: string; scMethod?: string; conditionsNotOnOrAfter?: string | null; audience?: string; inResponseTo?: string; responseInResponseTo?: string; nameId?: string; nameFormat?: string; email?: string; notOnOrAfter?: string; issuer?: string; key?: KeyObject; sign?: boolean }
function assertion(o: Opts): string {
  const sc = `<saml:SubjectConfirmation Method="${o.scMethod ?? "urn:oasis:names:tc:SAML:2.0:cm:bearer"}"><saml:SubjectConfirmationData InResponseTo="${o.inResponseTo ?? REQUEST_ID}" Recipient="${o.recipient ?? SP.acsUrl}" NotOnOrAfter="${o.scNotOnOrAfter ?? iso(300_000)}"/></saml:SubjectConfirmation>`;
  const attrs = o.email ? `<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${o.email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>` : "";
  return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion1" Version="2.0" IssueInstant="${iso(0)}"><saml:Issuer>${o.issuer ?? CONFIG.idpIssuer}</saml:Issuer>`
    + `<saml:Subject><saml:NameID Format="${o.nameFormat ?? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"}">${o.nameId ?? "Alice@Acme.com"}</saml:NameID>${sc}</saml:Subject>`
    + `<saml:Conditions${o.conditionsNotOnOrAfter === null ? "" : ` NotBefore="${iso(-60_000)}" NotOnOrAfter="${o.conditionsNotOnOrAfter ?? o.notOnOrAfter ?? iso(300_000)}"`}><saml:AudienceRestriction><saml:Audience>${o.audience ?? SP.spEntityId}</saml:Audience></saml:AudienceRestriction></saml:Conditions>${attrs}</saml:Assertion>`;
}
function signAssertion(xml: string, key: KeyObject): string {
  const s = new SignedXml({ privateKey: key.export({ format: "pem", type: "pkcs8" }) as string, signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" });
  s.addReference({ xpath: "//*[local-name(.)='Assertion']", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
  s.computeSignature(xml, { location: { reference: "//*[local-name(.)='Issuer']", action: "after" } });
  return s.getSignedXml();
}
// a valid signature over the Response, around an assertion that nobody signed
function signResponse(xml: string, key: KeyObject): string {
  const s = new SignedXml({ privateKey: key.export({ format: "pem", type: "pkcs8" }) as string, signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" });
  s.addReference({ xpath: "/*", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
  s.computeSignature(xml, { location: { reference: "//*[local-name(.)='Status']", action: "before" } });
  return s.getSignedXml();
}
const wrap = (inner: string, inResponseTo = REQUEST_ID) => `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp1" Version="2.0" IssueInstant="${iso(0)}" InResponseTo="${inResponseTo}"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${inner}</samlp:Response>`;
const b64xml = (xml: string) => Buffer.from(xml).toString("base64");
const signed = (o: Opts = {}) => wrap(o.sign === false ? assertion(o) : signAssertion(assertion(o), o.key ?? idpKeys.privateKey), o.responseInResponseTo);
const validate = (xml: string, requestId = REQUEST_ID) => samlValidate(CONFIG, { ...SP, samlResponse: b64xml(xml), requestId });

describe("SAML", () => {
  it("puts the request id in the AuthnRequest it returns", async () => {
    const { url, requestId } = await samlAuthorizeUrl(CONFIG, { ...SP, relayState: "rs" });
    const u = new URL(url);
    expect(u.origin + u.pathname).toBe(CONFIG.entryPoint);
    expect(u.searchParams.get("RelayState")).toBe("rs");
    const xml = inflateRawSync(Buffer.from(u.searchParams.get("SAMLRequest")!, "base64")).toString();
    expect(xml).toContain(`ID="${requestId}"`);
    expect(xml).toContain(`AssertionConsumerServiceURL="${SP.acsUrl}"`);
    expect(xml).toContain(SP.spEntityId);
  });

  it("accepts a signed assertion and reads the identity", async () => {
    await expect(validate(signed())).resolves.toEqual({ subject: "Alice@Acme.com", email: "alice@acme.com" });
  });

  it("reads the email attribute when the NameID is not an email", async () => {
    const r = signed({ nameId: "opaque-7", nameFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", email: "Bob@Acme.com" });
    await expect(validate(r)).resolves.toEqual({ subject: "opaque-7", email: "bob@acme.com" });
  });

  const good = signed();
  it.each([
    ["an unsigned assertion", /signature/i, () => signed({ sign: false })],
    ["an assertion signed by another key", /signature/i, () => signed({ key: rsaOther.privateKey })],
    ["the wrong audience", /audience/i, () => signed({ audience: "https://other-sp.example.com" })],
    ["an expired assertion", /expired/i, () => signed({ notOnOrAfter: iso(-3_600_000) })],
    ["the wrong IdP issuer", /issuer/, () => signed({ issuer: "https://evil.example.com/meta" })],
    ["a NameID changed after signing", /signature/i, () => good.replace("Alice@Acme.com", "admin@acme.com")],
    ["an assertion for another request", /answer to this sign-in/, () => signed({ inResponseTo: "_other" })],
    ["a wrong Recipient", /answer to this sign-in/, () => signed({ recipient: "https://evil.example.com/acs" })],
    ["an expired SubjectConfirmationData", /answer to this sign-in/, () => signed({ scNotOnOrAfter: iso(-3_600_000) })],
    ["a holder-of-key confirmation only", /answer to this sign-in/, () => signed({ scMethod: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key" })],
    ["Conditions with no validity period", /validity period/, () => signed({ conditionsNotOnOrAfter: null })],
    ["a signed Response around an unsigned assertion", /signature/i, () => signResponse(signed({ sign: false }), idpKeys.privateKey)],
    ["a forged Response InResponseTo", /answer to this sign-in/, () => signed({ inResponseTo: "_other", responseInResponseTo: REQUEST_ID })],
    ["a forged assertion beside a signed one in Extensions", /signature/i, () => {
      const s = signAssertion(assertion({}), idpKeys.privateKey);
      return wrap(`<samlp:Extensions>${s}</samlp:Extensions>${assertion({ nameId: "admin@acme.com" })}`);
    }],
  ])("refuses %s", async (_name, error, make) => {
    await expect(validate(make())).rejects.toThrow(error);
  });

  it("refuses a response that answers a different request id", async () => {
    await expect(validate(good, "_not_mine")).rejects.toThrow(/answer to this sign-in/);
  });
});
