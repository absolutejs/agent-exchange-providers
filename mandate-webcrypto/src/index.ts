import type {
  AgentExchangeMandateJwsSigner,
  AgentExchangeMandateJwsVerifier,
  AgentExchangeMandatePrincipal,
} from "@absolutejs/agent-exchange";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const MAX_JWS_BYTES = 64 * 1024;

const asArrayBuffer = (value: Uint8Array): ArrayBuffer =>
  Uint8Array.from(value).buffer;

const toBase64Url = (value: Uint8Array): string => {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

const fromBase64Url = (value: string): Uint8Array => {
  if (!/^[A-Za-z0-9_-]+$/u.test(value) || value.length > MAX_JWS_BYTES)
    throw new Error("invalid mandate JWS");
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (toBase64Url(bytes) !== value) throw new Error("invalid mandate JWS");
  return bytes;
};

const validKeyId = (value: string): boolean =>
  value.length >= 1 &&
  value.length <= 256 &&
  /^[A-Za-z0-9._~:-]+$/u.test(value);

const assertP256Key = (key: CryptoKey, usage: "sign" | "verify"): void => {
  const algorithm = key.algorithm as EcKeyAlgorithm;
  if (
    key.algorithm.name !== "ECDSA" ||
    algorithm.namedCurve !== "P-256" ||
    !key.usages.includes(usage) ||
    (usage === "sign" && (key.type !== "private" || key.extractable)) ||
    (usage === "verify" && key.type !== "public")
  )
    throw new Error("mandate JWS requires an ES256 key");
};

export type AgentExchangeMandatePublicKeyResolver = {
  readonly resolve: (input: {
    readonly issuer: AgentExchangeMandatePrincipal;
    readonly keyId: string;
  }) => Promise<CryptoKey> | CryptoKey;
};

export const createWebCryptoMandateJwsSigner = (options: {
  readonly keyId: string;
  readonly privateKey: CryptoKey;
}): AgentExchangeMandateJwsSigner => {
  if (!validKeyId(options.keyId)) throw new Error("invalid mandate JWS key ID");
  assertP256Key(options.privateKey, "sign");
  return Object.freeze({
    sign: async ({ payload, type }) => {
      if (payload.byteLength < 1 || payload.byteLength > MAX_JWS_BYTES)
        throw new Error("invalid mandate JWS payload");
      const protectedHeader = toBase64Url(
        encoder.encode(
          JSON.stringify({ alg: "ES256", kid: options.keyId, typ: type }),
        ),
      );
      const encodedPayload = toBase64Url(payload);
      const signingInput = `${protectedHeader}.${encodedPayload}`;
      const signature = new Uint8Array(
        await crypto.subtle.sign(
          { hash: "SHA-256", name: "ECDSA" },
          options.privateKey,
          encoder.encode(signingInput),
        ),
      );
      if (signature.byteLength !== 64)
        throw new Error("invalid ES256 signature encoding");
      return `${signingInput}.${toBase64Url(signature)}`;
    },
  });
};

export const createWebCryptoMandateJwsVerifier = (options: {
  readonly keys: AgentExchangeMandatePublicKeyResolver;
}): AgentExchangeMandateJwsVerifier =>
  Object.freeze({
    verify: async ({ compactJws, expectedIssuer, type }) => {
      if (encoder.encode(compactJws).byteLength > MAX_JWS_BYTES * 2)
        throw new Error("invalid mandate JWS");
      const parts = compactJws.split(".");
      if (parts.length !== 3 || parts.some((part) => part.length === 0))
        throw new Error("invalid mandate JWS");
      const [protectedPart, payloadPart, signaturePart] = parts as [
        string,
        string,
        string,
      ];
      const headerValue: unknown = JSON.parse(
        decoder.decode(fromBase64Url(protectedPart)),
      );
      if (
        typeof headerValue !== "object" ||
        headerValue === null ||
        Array.isArray(headerValue)
      )
        throw new Error("invalid mandate JWS header");
      const header = headerValue as Record<string, unknown>;
      if (
        Object.keys(header).length !== 3 ||
        header.alg !== "ES256" ||
        header.typ !== type ||
        typeof header.kid !== "string" ||
        !validKeyId(header.kid)
      )
        throw new Error("invalid mandate JWS header");
      const publicKey = await options.keys.resolve({
        issuer: expectedIssuer,
        keyId: header.kid,
      });
      assertP256Key(publicKey, "verify");
      const signature = fromBase64Url(signaturePart);
      if (signature.byteLength !== 64)
        throw new Error("invalid ES256 signature encoding");
      const verified = await crypto.subtle.verify(
        { hash: "SHA-256", name: "ECDSA" },
        publicKey,
        asArrayBuffer(signature),
        encoder.encode(`${protectedPart}.${payloadPart}`),
      );
      if (!verified) throw new Error("invalid mandate JWS signature");
      return {
        algorithm: "ES256",
        keyId: header.kid,
        payload: fromBase64Url(payloadPart),
      };
    },
  });
