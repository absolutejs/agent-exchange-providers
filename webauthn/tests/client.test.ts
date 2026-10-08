import { expect, mock, test } from "bun:test";
let rejectDevice = false;
let assertions = 0;
mock.module("@simplewebauthn/browser", () => ({
  startAuthentication: async () => {
    assertions++;
    if (rejectDevice) throw new Error("Cancelled");
    return { id: "credential" };
  },
}));
const { approveAgentExchangeWithPasskey } = await import("../src/client");
test("preserves the server approval identifier and does not verify a cancelled ceremony", async () => {
  const options = { challenge: "challenge", rpId: "example.com" };
  let verified = 0;
  const input = {
    begin: async () => ({ approvalId: "server-approval", options }),
    verify: async ({ approvalId }: { approvalId: string }) => {
      verified++;
      return approvalId;
    },
  };
  expect(await approveAgentExchangeWithPasskey(input)).toBe("server-approval");
  rejectDevice = true;
  await expect(approveAgentExchangeWithPasskey(input)).rejects.toThrow(
    "Cancelled",
  );
  expect(verified).toBe(1);
  const before = assertions;
  await expect(
    approveAgentExchangeWithPasskey({
      ...input,
      begin: async () => ({ approvalId: "", options }),
    }),
  ).rejects.toThrow("Missing");
  expect(assertions).toBe(before);
});
