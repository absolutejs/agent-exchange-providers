import { describe, expect, test } from "bun:test";
import { verifyDpopProof } from "@absolutejs/agent-exchange-provider-conformance";
import { createWebCryptoDpopProofSigner } from "../src";

describe("WebCrypto DPoP signer", () => {
  test("creates verifiable method, URI, nonce, and access-token-bound proofs", async () => {
    const signer = await createWebCryptoDpopProofSigner({
      now: () => 1_000_000,
      randomBytes: () => new Uint8Array(16).fill(7),
    });
    const proof = await signer.createProof({
      accessToken: "secret-access-token",
      htm: "GET",
      htu: "https://api.example/messages?unbound=query#fragment",
      nonce: "server-nonce",
    });
    const publicJwk = await verifyDpopProof({
      accessToken: "secret-access-token",
      htm: "GET",
      htu: "https://api.example/messages?different=query",
      nonce: "server-nonce",
      now: () => 1_000_000,
      proof,
    });
    expect(publicJwk).toEqual(signer.publicJwk);
    expect("d" in signer.publicJwk).toBe(false);
  });

  test("fails verification after purpose, nonce, token, or signature changes", async () => {
    const signer = await createWebCryptoDpopProofSigner({
      now: () => 2_000_000,
    });
    const proof = await signer.createProof({
      accessToken: "token-a",
      htm: "POST",
      htu: "https://api.example/submit",
      nonce: "nonce-a",
    });
    await expect(
      verifyDpopProof({
        accessToken: "token-b",
        htm: "POST",
        htu: "https://api.example/submit",
        nonce: "nonce-a",
        now: () => 2_000_000,
        proof,
      }),
    ).rejects.toThrow("access-token hash");
    const tampered = `${proof.slice(0, -1)}${proof.endsWith("A") ? "B" : "A"}`;
    await expect(
      verifyDpopProof({
        accessToken: "token-a",
        htm: "POST",
        htu: "https://api.example/submit",
        nonce: "nonce-a",
        now: () => 2_000_000,
        proof: tampered,
      }),
    ).rejects.toThrow("signature");
  });
});
