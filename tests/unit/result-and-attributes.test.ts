import { describe, expect, it } from "vitest";

import { customDeviceAttribute } from "../../src/device-attributes.js";
import { UdidToolsError, toUdidToolsError } from "../../src/errors.js";
import { failure, resultify, success, unwrapResult } from "../../src/result.js";
import { isKnownDeviceAttribute } from "../../src/validation/profile-service.js";

describe("public utility contracts", () => {
  it("brands only syntactically safe custom device attributes", () => {
    expect(customDeviceAttribute("FUTURE_DEVICE_ID_2")).toBe("FUTURE_DEVICE_ID_2");
    expect(() => customDeviceAttribute("future-device-id")).toThrow(
      expect.objectContaining({ code: "INVALID_CONFIGURATION" })
    );
  });

  it("distinguishes known device attributes at runtime", () => {
    expect(isKnownDeviceAttribute("UDID")).toBe(true);
    expect(isKnownDeviceAttribute("FUTURE_DEVICE_ID")).toBe(false);
  });

  it("constructs, unwraps, and preserves successful results", () => {
    const warning = { code: "INSECURE_RESPONSE_URL" as const, message: "Use HTTPS." };
    expect(success(42)).toEqual({ ok: true, value: 42, warnings: [] });
    expect(success(42, [warning])).toEqual({ ok: true, value: 42, warnings: [warning] });
    expect(unwrapResult(success("value"))).toBe("value");
  });

  it("normalizes unknown failures without leaking their details", () => {
    const secret = new Error("secret-bearing failure");
    const normalized = failure(secret);
    expect(normalized).toMatchObject({
      error: { code: "INTERNAL_ERROR", message: "An unexpected library error occurred." },
      ok: false,
    });
    expect(normalized.ok || normalized.error).not.toHaveProperty("cause");
    expect(toUdidToolsError(secret).message).not.toContain("secret-bearing");
  });

  it("preserves typed failures and throws them only when explicitly unwrapped", () => {
    const error = new UdidToolsError("INVALID_CONFIGURATION", "Invalid input.", {
      details: { field: "profile" },
    });
    const result = failure(error);
    expect(result).toEqual({ error, ok: false });
    expect(toUdidToolsError(error)).toBe(error);
    expect(() => unwrapResult(result)).toThrow(error);
  });

  it("turns both promise outcomes into Result values", async () => {
    await expect(resultify(() => Promise.resolve("done"))).resolves.toEqual({
      ok: true,
      value: "done",
      warnings: [],
    });
    await expect(
      resultify(() => Promise.reject(new UdidToolsError("INVALID_CONFIGURATION", "Invalid input.")))
    ).resolves.toMatchObject({ error: { code: "INVALID_CONFIGURATION" }, ok: false });
  });
});
