import { normalizeDpopHtu } from "@absolutejs/agent-exchange-provider-conformance";
import type { DpopProofSigner } from "@absolutejs/agent-exchange-oauth";

const encoder = new TextEncoder();

const toBase64Url = (value: Uint8Array): string => {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

const encodeJson = (value: unknown): string =>
  toBase64Url(encoder.encode(JSON.stringify(value)));

const hash = async (value: string): Promise<string> =>
  toBase64Url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(value)),
    ),
  );

export type WebCryptoDpopProofSigner = DpopProofSigner & {
  readonly publicJwk: Readonly<JsonWebKey>;
};

export type WebCryptoDpopProofSignerOptions = {
  readonly keyPair?: CryptoKeyPair;
  readonly now?: () => number;
  readonly randomBytes?: (length: number) => Uint8Array;
};

const validateKeyPair = (keyPair: CryptoKeyPair): void => {
  if (
    keyPair.privateKey.type !== "private" ||
    keyPair.privateKey.extractable ||
    keyPair.privateKey.algorithm.name !== "ECDSA" ||
    !keyPair.privateKey.usages.includes("sign") ||
    keyPair.publicKey.type !== "public" ||
    keyPair.publicKey.algorithm.name !== "ECDSA"
  )
    throw new Error("DPoP requires a non-exportable ECDSA P-256 signing key");
};

export const createWebCryptoDpopProofSigner = async (
  options: WebCryptoDpopProofSignerOptions = {},
): Promise<WebCryptoDpopProofSigner> => {
  const keyPair =
    options.keyPair ??
    ((await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    )) as CryptoKeyPair);
  validateKeyPair(keyPair);
  const publicJwk = Object.freeze(
    await crypto.subtle.exportKey("jwk", keyPair.publicKey),
  );
  if (
    publicJwk.kty !== "EC" ||
    publicJwk.crv !== "P-256" ||
    typeof publicJwk.x !== "string" ||
    typeof publicJwk.y !== "string" ||
    publicJwk.d !== undefined
  )
    throw new Error("DPoP public key export failed");
  const now = options.now ?? Date.now;
  const randomBytes =
    options.randomBytes ??
    ((length: number) => crypto.getRandomValues(new Uint8Array(length)));

  return Object.freeze({
    createProof: async (
      input: Parameters<DpopProofSigner["createProof"]>[0],
    ) => {
      const { accessToken, htm, htu, nonce } = input;
      if (!/^[A-Z]+$/u.test(htm))
        throw new Error("DPoP htm must be an uppercase HTTP method");
      if (nonce !== undefined && (nonce.length === 0 || nonce.length > 1024))
        throw new Error("DPoP nonce is invalid");
      const jtiBytes = randomBytes(16);
      if (!(jtiBytes instanceof Uint8Array) || jtiBytes.byteLength !== 16)
        throw new Error("DPoP random source must return exactly 16 bytes");
      const header = encodeJson({
        alg: "ES256",
        jwk: publicJwk,
        typ: "dpop+jwt",
      });
      const payload = encodeJson({
        ...(accessToken === undefined ? {} : { ath: await hash(accessToken) }),
        htm,
        htu: normalizeDpopHtu(htu),
        iat: Math.floor(now() / 1000),
        jti: toBase64Url(jtiBytes),
        ...(nonce === undefined ? {} : { nonce }),
      });
      const signingInput = `${header}.${payload}`;
      const signature = new Uint8Array(
        await crypto.subtle.sign(
          { hash: "SHA-256", name: "ECDSA" },
          keyPair.privateKey,
          encoder.encode(signingInput),
        ),
      );
      return `${signingInput}.${toBase64Url(signature)}`;
    },
    publicJwk,
  });
};
