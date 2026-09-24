import {
  startAuthentication,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";

/** Run only after the user reviews the exact service and teammate grant.
 * The server must bind approvalId to the session and immutable mandate draft,
 * atomically consume it, and verify the assertion with the mandate provider. */
export const approveAgentExchangeWithPasskey = async <Result>(input: {
  readonly begin: () => Promise<{
    readonly approvalId: string;
    readonly options: PublicKeyCredentialRequestOptionsJSON;
  }>;
  readonly verify: (input: {
    readonly approvalId: string;
    readonly response: AuthenticationResponseJSON;
  }) => Promise<Result>;
}): Promise<Result> => {
  const pending = await input.begin();
  if (!pending.approvalId) throw new Error("Missing approval ceremony");
  const response = await startAuthentication({ optionsJSON: pending.options });
  return input.verify({ approvalId: pending.approvalId, response });
};
