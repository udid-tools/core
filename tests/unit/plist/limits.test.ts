import { describe, expect, it } from "vitest";

import { UdidToolsError } from "../../../src/errors.js";
import { decodePlist, encodePlist } from "../../../src/plist/index.js";

function captureError(operation: () => unknown): UdidToolsError {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(UdidToolsError);
    return error as UdidToolsError;
  }
  throw new Error("Expected the operation to fail.");
}

function expectLimit(
  operation: () => unknown,
  limit: string,
  code: "INPUT_TOO_LARGE" | "OUTPUT_TOO_LARGE" = "INPUT_TOO_LARGE"
): void {
  const error = captureError(operation);
  expect(error.code).toBe(code);
  expect(error.details?.["limit"]).toBe(limit);
}

describe("plist resource limits", () => {
  it("enforces maxInputBytes for strings and byte arrays", () => {
    const source = '<plist version="1.0"><string>x</string></plist>';

    expectLimit(() => decodePlist(source, { maxInputBytes: 10 }), "maxInputBytes");
    expectLimit(
      () => decodePlist(new TextEncoder().encode(source), { maxInputBytes: 10 }),
      "maxInputBytes"
    );
  });

  it("enforces maxOutputBytes while constructing XML", () => {
    expectLimit(
      () => encodePlist("x", { maxOutputBytes: 32 }),
      "maxOutputBytes",
      "OUTPUT_TOO_LARGE"
    );
  });

  it("enforces maxStringBytes on values and dictionary keys", () => {
    const valueSource = '<plist version="1.0"><string>three</string></plist>';
    const keySource =
      '<plist version="1.0"><dict><key>three</key><string>x</string></dict></plist>';

    expectLimit(() => decodePlist(valueSource, { maxStringBytes: 4 }), "maxStringBytes");
    expectLimit(() => decodePlist(keySource, { maxStringBytes: 4 }), "maxStringBytes");
    expectLimit(() => encodePlist("three", { maxStringBytes: 4 }), "maxStringBytes");
    expectLimit(() => encodePlist({ three: "x" }, { maxStringBytes: 4 }), "maxStringBytes");
  });

  it("measures string limits in UTF-8 bytes", () => {
    expectLimit(() => encodePlist("😀", { maxStringBytes: 3 }), "maxStringBytes");
    expectLimit(
      () => decodePlist('<plist version="1.0"><string>😀</string></plist>', { maxStringBytes: 3 }),
      "maxStringBytes"
    );
  });

  it("enforces maxArrayItems while encoding and decoding", () => {
    const source =
      '<plist version="1.0"><array><string>a</string><string>b</string></array></plist>';

    expectLimit(() => encodePlist(["a", "b"], { maxArrayItems: 1 }), "maxArrayItems");
    expectLimit(() => decodePlist(source, { maxArrayItems: 1 }), "maxArrayItems");
  });

  it("enforces maxDictionaryKeys while encoding and decoding", () => {
    const source =
      '<plist version="1.0"><dict>' +
      "<key>a</key><string>x</string><key>b</key><string>y</string>" +
      "</dict></plist>";

    expectLimit(
      () => encodePlist({ a: "x", b: "y" }, { maxDictionaryKeys: 1 }),
      "maxDictionaryKeys"
    );
    expectLimit(() => decodePlist(source, { maxDictionaryKeys: 1 }), "maxDictionaryKeys");
  });

  it("enforces semantic plist depth while encoding and decoding", () => {
    const source =
      '<plist version="1.0"><dict><key>a</key><dict><key>b</key><string>x</string></dict></dict></plist>';

    expectLimit(() => encodePlist({ a: { b: "x" } }, { maxPlistDepth: 2 }), "maxPlistDepth");
    expectLimit(() => decodePlist(source, { maxPlistDepth: 2 }), "maxPlistDepth");
  });

  it("allows values exactly at configured boundaries", () => {
    const source =
      '<plist version="1.0"><dict><key>a</key><array><string>four</string></array></dict></plist>';

    expect(
      decodePlist(source, {
        maxArrayItems: 1,
        maxDictionaryKeys: 1,
        maxPlistDepth: 3,
        maxStringBytes: 4,
      })
    ).toEqual({ a: ["four"] });
  });
});
