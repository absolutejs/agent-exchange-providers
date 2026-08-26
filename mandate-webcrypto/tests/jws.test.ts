import { expect, test } from "bun:test";
import {
  createWebCryptoMandateJwsSigner,
  createWebCryptoMandateJwsVerifier,
} from "../src";

const generateKeys = () =>
  crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]) as Promise<CryptoKeyPair>;

test("signs and verifies an explicitly typed issuer-bound ES256 JWS", async () => {
  const keys = await generateKeys();
  const issuer = { authority: "https://owner.example", subject: "owner-1" };
  const signer = createWebCryptoMandateJwsSigner({
    keyId: "key-1",
    privateKey: keys.privateKey,
  });
  const verifier = createWebCryptoMandateJwsVerifier({
    keys: {
      resolve: ({ issuer: actualIssuer, keyId }) => {
        expect(actualIssuer).toEqual(issuer);
        expect(keyId).toBe("key-1");
        return keys.publicKey;
      },
    },
  });
  const payload = new TextEncoder().encode('{"version":1}');
  const compactJws = await signer.sign({
    payload,
    type: "absolute-agent-exchange-mandate+jws",
  });
  await expect(
    verifier.verify({
      compactJws,
      expectedIssuer: issuer,
      type: "absolute-agent-exchange-mandate+jws",
    }),
  ).resolves.toMatchObject({ algorithm: "ES256", keyId: "key-1", payload });
});

test("rejects tampering and algorithm substitution", async () => {
  const keys = await generateKeys();
  const signer = createWebCryptoMandateJwsSigner({
    keyId: "key-1",
    privateKey: keys.privateKey,
  });
  const verifier = createWebCryptoMandateJwsVerifier({
    keys: { resolve: () => keys.publicKey },
  });
  const compactJws = await signer.sign({
    payload: new TextEncoder().encode('{"version":1}'),
    type: "absolute-agent-exchange-mandate+jws",
  });
  const [header, payload, signature] = compactJws.split(".") as [
    string,
    string,
    string,
  ];
  const input = {
    expectedIssuer: {
      authority: "https://owner.example",
      subject: "owner-1",
    },
    type: "absolute-agent-exchange-mandate+jws" as const,
  };
  await expect(
    verifier.verify({
      ...input,
      compactJws: `${header}.${payload}A.${signature}`,
    }),
  ).rejects.toThrow();

  const noneHeader = Buffer.from(
    JSON.stringify({ alg: "none", kid: "key-1", typ: input.type }),
  ).toString("base64url");
  await expect(
    verifier.verify({
      ...input,
      compactJws: `${noneHeader}.${payload}.${signature}`,
    }),
  ).rejects.toThrow();
});
