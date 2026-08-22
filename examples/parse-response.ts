import { parseProfileServiceResponse } from "@udid-tools/core";

export async function handleProfileResponse(
  body: Uint8Array,
  expectedChallenge: string,
  trustAnchors: readonly Uint8Array[]
): Promise<string> {
  const result = await parseProfileServiceResponse(body, {
    expectedChallenge: { type: "string", value: expectedChallenge },
    requiredAttributes: ["UDID"],
    verification: { mode: "trust-chain", trustAnchors },
  });

  if (!result.ok) {
    throw result.error;
  }

  const udid = result.value.attributes.udid;
  if (udid === undefined) {
    throw new Error("The parser contract did not return the required UDID.");
  }
  return udid;
}
