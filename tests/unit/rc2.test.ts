import { describe, expect, it } from "vitest";

import { decryptRc2Cbc } from "../../src/certificates/rc2.js";

// All eight published vectors from RFC 2268, section 5, tested as CBC with a zero IV.
const vectors = [
  ["0000000000000000", 63, "0000000000000000", "ebb773f993278eff"],
  ["ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"],
  ["3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"],
  ["88", 64, "0000000000000000", "61a8a244adacccf0"],
  ["88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"],
  ["88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000", "1a807d272bbe5db1"],
  ["88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000", "2269552ab0f85ca6"],
  [
    "88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e",
    129,
    "0000000000000000",
    "5b78d3a43dfff1f1",
  ],
] as const;

describe("legacy PKCS#12 RC2-CBC decryption", () => {
  it.each(vectors)(
    "decrypts RFC 2268 vector with key %s and %i effective bits",
    (key, bits, plain, cipher) => {
      expect(
        Buffer.from(
          decryptRc2Cbc(
            Buffer.from(cipher, "hex"),
            Buffer.from(key, "hex"),
            new Uint8Array(8),
            bits
          )
        ).toString("hex")
      ).toBe(plain);
    }
  );

  it("applies the supplied CBC IV and previous ciphertext blocks without changing inputs", () => {
    const key = Buffer.from("88bca90e90875a7f0f79c384627bafb2", "hex");
    const block = Buffer.from("2269552ab0f85ca6", "hex");
    const encrypted = Buffer.concat([block, block]);
    const iv = Buffer.from("0102030405060708", "hex");
    // The vector decrypts each block to zero before CBC XOR.
    expect(Buffer.from(decryptRc2Cbc(encrypted, key, iv, 128))).toEqual(Buffer.concat([iv, block]));
    expect(encrypted).toEqual(Buffer.concat([block, block]));
    expect(key.toString("hex")).toBe("88bca90e90875a7f0f79c384627bafb2");
    expect(iv.toString("hex")).toBe("0102030405060708");
  });

  it.each([
    { encrypted: new Uint8Array() },
    { encrypted: new Uint8Array(7) },
    { key: new Uint8Array() },
    { key: new Uint8Array(129) },
    { iv: new Uint8Array(7) },
    { iv: new Uint8Array(9) },
    { bits: 0 },
    { bits: 1025 },
    { bits: 1.5 },
    { bits: Number.NaN },
  ])("rejects invalid block, key, IV, or effective-key bounds %#", (invalid) => {
    expect(() =>
      decryptRc2Cbc(
        invalid.encrypted ?? new Uint8Array(8),
        invalid.key ?? new Uint8Array(5),
        invalid.iv ?? new Uint8Array(8),
        invalid.bits ?? 40
      )
    ).toThrow("Invalid PKCS#12 RC2 parameters.");
  });
});
