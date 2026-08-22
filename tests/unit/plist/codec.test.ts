import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { UdidToolsError } from "../../../src/errors.js";
import { decodePlist, encodePlist } from "../../../src/plist/index.js";
import type { PlistValue } from "../../../src/types.js";

function xml(value: PlistValue): string {
  return new TextDecoder().decode(encodePlist(value));
}

function captureError(operation: () => unknown): UdidToolsError {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(UdidToolsError);
    return error as UdidToolsError;
  }
  throw new Error("Expected the operation to fail.");
}

describe("plist codec", () => {
  it("round-trips every supported plist value type", () => {
    const input: PlistValue = {
      array: ["text", 7, 1.25, true, false],
      data: Uint8Array.from([0, 1, 2, 253, 254, 255]),
      date: new Date("2026-08-22T01:02:03.456Z"),
      emptyArray: [],
      emptyData: new Uint8Array(),
      emptyDictionary: {},
      emptyString: "",
      nested: { value: "inside" },
    };

    expect(decodePlist(encodePlist(input))).toEqual(input);
  });

  it("encodes integers, reals, and negative zero with their correct tags", () => {
    const output = xml([0, -2, 1.5, -0]);

    expect(output).toContain("<integer>0</integer>");
    expect(output).toContain("<integer>-2</integer>");
    expect(output).toContain("<real>1.5</real>");
    expect(output).toContain("<real>-0</real>");

    const decoded = decodePlist(encodePlist([-0]));
    expect(Array.isArray(decoded)).toBe(true);
    expect(Object.is((decoded as readonly PlistValue[])[0], -0)).toBe(true);
  });

  it("uses deterministic key ordering and XML escaping", () => {
    const output = xml({
      z: "last",
      a: `&<>"'\r\n`,
    });

    expect(output.indexOf("<key>a</key>")).toBeLessThan(output.indexOf("<key>z</key>"));
    expect(output).toContain("&amp;&lt;&gt;&quot;&apos;&#13;\n");
    expect(decodePlist(output)).toEqual({ a: `&<>"'\r\n`, z: "last" });
  });

  it("accepts the standard Apple prolog and documents without a prolog", () => {
    const withProlog = xml("hello");
    const withoutProlog = '<plist version="1.0"><string>hello</string></plist>';

    expect(decodePlist(withProlog)).toBe("hello");
    expect(decodePlist(withoutProlog)).toBe("hello");
  });

  it("accepts both string and Uint8Array input", () => {
    const source = '<plist version="1.0"><integer>42</integer></plist>';

    expect(decodePlist(source)).toBe(42);
    expect(decodePlist(new TextEncoder().encode(source))).toBe(42);
  });

  it("decodes whitespace-formatted base64 data", () => {
    const source = '<plist version="1.0"><data>\n  AAECAwQF\n  /f7/\n</data></plist>';

    expect(decodePlist(source)).toEqual(Uint8Array.from([0, 1, 2, 3, 4, 5, 253, 254, 255]));
  });

  it("decodes ISO dates with or without fractional seconds", () => {
    expect(decodePlist('<plist version="1.0"><date>2026-08-22T01:02:03Z</date></plist>')).toEqual(
      new Date("2026-08-22T01:02:03.000Z")
    );
    expect(decodePlist('<plist version="1.0"><date>2026-08-22T01:02:03.4Z</date></plist>')).toEqual(
      new Date("2026-08-22T01:02:03.400Z")
    );
  });

  it("returns dictionaries with no prototype", () => {
    const decoded = decodePlist(
      '<plist version="1.0"><dict><key>safe</key><string>value</string></dict></plist>'
    );

    expect(Object.getPrototypeOf(decoded)).toBeNull();
    expect(decoded).toEqual({ safe: "value" });
  });

  it("encodes Buffer values as plist data without exposing Buffer in the result", () => {
    const decoded = decodePlist(encodePlist(Buffer.from("hello")));

    expect(decoded).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(decoded as Uint8Array).toString("utf8")).toBe("hello");
  });

  it("returns typed errors", () => {
    const error = captureError(() => decodePlist("not xml"));

    expect(error.code).toBe("MALFORMED_PLIST");
    expect(error.message).not.toContain("not xml");
  });
});
