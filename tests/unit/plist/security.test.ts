import { describe, expect, it } from "vitest";

import { UdidToolsError } from "../../../src/errors.js";
import { decodePlist, encodePlist } from "../../../src/plist/index.js";
import type { PlistValue } from "../../../src/types.js";

function captureError(operation: () => unknown): UdidToolsError {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(UdidToolsError);
    return error as UdidToolsError;
  }
  throw new Error("Expected the operation to fail.");
}

function expectMalformed(source: string): void {
  expect(captureError(() => decodePlist(source)).code).toBe("MALFORMED_PLIST");
}

describe("plist decoder security", () => {
  it("rejects malformed XML", () => {
    expectMalformed('<plist version="1.0"><dict></plist>');
    expectMalformed('<plist version="1.0"><string>x</string></plist><plist version="1.0"/>');
    expectMalformed('text<plist version="1.0"><string>x</string></plist>');
  });

  it("rejects custom DTDs and entity declarations", () => {
    expectMalformed(`<!DOCTYPE plist [
      <!ENTITY secret SYSTEM "file:///etc/passwd">
    ]><plist version="1.0"><string>&secret;</string></plist>`);
    expectMalformed(`<!DOCTYPE plist PUBLIC "untrusted" "https://example.com/plist.dtd">
      <plist version="1.0"><string>x</string></plist>`);
  });

  it("rejects comments, CDATA, and processing instructions", () => {
    expectMalformed('<plist version="1.0"><!-- hidden --><string>x</string></plist>');
    expectMalformed('<plist version="1.0"><string><![CDATA[x]]></string></plist>');
    expectMalformed('<plist version="1.0"><?custom value?><string>x</string></plist>');
  });

  it("rejects duplicate dictionary keys", () => {
    expectMalformed(
      '<plist version="1.0"><dict>' +
        "<key>same</key><string>first</string>" +
        "<key>same</key><string>second</string>" +
        "</dict></plist>"
    );
  });

  it.each(["__proto__", "constructor", "prototype", "__defineGetter__"])(
    "rejects unsafe dictionary key %s while decoding",
    (key) => {
      expectMalformed(
        `<plist version="1.0"><dict><key>${key}</key><string>x</string></dict></plist>`
      );
    }
  );

  it("rejects dictionaries whose key/value sequence is malformed", () => {
    expectMalformed('<plist version="1.0"><dict><string>x</string><key>a</key></dict></plist>');
    expectMalformed('<plist version="1.0"><dict><key>a</key></dict></plist>');
    expectMalformed(
      '<plist version="1.0"><dict><key>a</key><key>b</key><string>x</string><string>y</string></dict></plist>'
    );
  });

  it("rejects unsupported tags and misplaced key elements", () => {
    expectMalformed('<plist version="1.0"><uid>1</uid></plist>');
    expectMalformed('<plist version="1.0"><key>outside</key></plist>');
  });

  it("rejects attributes on value elements", () => {
    expectMalformed('<plist version="1.0"><string lang="en">x</string></plist>');
    expectMalformed('<plist version="1.0"><array custom="x"/></plist>');
  });

  it("requires one version 1.0 plist root and exactly one value", () => {
    expectMalformed("<plist><string>x</string></plist>");
    expectMalformed('<plist version="2.0"><string>x</string></plist>');
    expectMalformed('<plist version="1.0" extra="x"><string>x</string></plist>');
    expectMalformed('<plist version="1.0"/>');
    expectMalformed('<plist version="1.0"><string>x</string><string>y</string></plist>');
    expectMalformed('<root version="1.0"><string>x</string></root>');
  });

  it("rejects malformed numbers and non-finite numeric representations", () => {
    expectMalformed('<plist version="1.0"><integer>1.5</integer></plist>');
    expectMalformed('<plist version="1.0"><integer>9007199254740992</integer></plist>');
    expectMalformed('<plist version="1.0"><real>NaN</real></plist>');
    expectMalformed('<plist version="1.0"><real>Infinity</real></plist>');
    expectMalformed('<plist version="1.0"><real>1e9999</real></plist>');
  });

  it("rejects invalid dates and base64", () => {
    expectMalformed('<plist version="1.0"><date>2026-02-30T00:00:00Z</date></plist>');
    expectMalformed('<plist version="1.0"><date>2026-01-01</date></plist>');
    expectMalformed('<plist version="1.0"><data>not-base64!</data></plist>');
    expectMalformed('<plist version="1.0"><data>AB==</data></plist>');
  });

  it("rejects non-empty boolean elements", () => {
    expectMalformed('<plist version="1.0"><true>text</true></plist>');
    expectMalformed('<plist version="1.0"><false> </false></plist>');
  });

  it("rejects invalid UTF-8", () => {
    const error = captureError(() => decodePlist(Uint8Array.from([0xc3, 0x28])));
    expect(error.code).toBe("MALFORMED_PLIST");
  });
});

describe("plist encoder security", () => {
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, 2 ** 53])(
    "rejects unsafe number %s",
    (value) => {
      expect(captureError(() => encodePlist(value)).code).toBe("MALFORMED_PLIST");
    }
  );

  it("rejects invalid dates", () => {
    expect(captureError(() => encodePlist(new Date(Number.NaN))).code).toBe("MALFORMED_PLIST");
  });

  it("rejects XML-invalid characters and lone surrogates", () => {
    expect(captureError(() => encodePlist("contains\u0000null")).code).toBe("MALFORMED_PLIST");
    expect(captureError(() => encodePlist("lone\ud800surrogate")).code).toBe("MALFORMED_PLIST");
  });

  it.each(["__proto__", "constructor", "prototype", "__lookupSetter__"])(
    "rejects unsafe dictionary key %s while encoding",
    (key) => {
      const value = Object.create(null) as Record<string, PlistValue>;
      value[key] = "x";
      expect(captureError(() => encodePlist(value)).code).toBe("MALFORMED_PLIST");
    }
  );

  it("rejects cyclic input", () => {
    const value: Record<string, PlistValue> = {};
    value["self"] = value;

    expect(captureError(() => encodePlist(value)).code).toBe("MALFORMED_PLIST");
  });

  it("rejects class instances, symbol keys, accessors, and non-enumerable values", () => {
    class Example {
      value = "x";
    }
    expect(captureError(() => encodePlist(new Example() as unknown as PlistValue)).code).toBe(
      "MALFORMED_PLIST"
    );

    const withSymbol = { value: "x", [Symbol("secret")]: "hidden" };
    expect(captureError(() => encodePlist(withSymbol)).code).toBe("MALFORMED_PLIST");

    const withGetter = Object.defineProperty({}, "value", {
      enumerable: true,
      get: () => "x",
    });
    expect(captureError(() => encodePlist(withGetter as PlistValue)).code).toBe("MALFORMED_PLIST");

    const nonEnumerable = Object.defineProperty({}, "value", {
      enumerable: false,
      value: "x",
    });
    expect(captureError(() => encodePlist(nonEnumerable as PlistValue)).code).toBe(
      "MALFORMED_PLIST"
    );
  });
});
