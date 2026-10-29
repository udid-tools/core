// RFC 2268, sections 2 and 4. Decryption only: legacy PKCS#12 input compatibility.
// This internal primitive is deliberately absent from the package exports.
const PI_TABLE = Buffer.from(
  "d978f9c419ddb5ed28e9fd794aa0d89d" +
    "c67e37832b76538e624c6488448bfba2" +
    "179a59f587b34f1361456d8d09817d32" +
    "bd8f40eb86b77b0bf09521225c6b4e82" +
    "54d66593ce60b21c7356c014a78cf1dc" +
    "1275ca1f3bbee4d1423dd430a33cb626" +
    "6fbf0eda4669075727f21d9bbc944303" +
    "f811c7f690ef3ee706c3d52fc8661ed7" +
    "08e8eade8052eef784aa72ac354d6a2a" +
    "961ad2715a1549744b9fd05e0418a4ec" +
    "c2e0416e0f51cbcc2491af50a1f47039" +
    "997c3a8523b8b47afc02365b25559731" +
    "2d5dfa98e38a92ae05df2910676cbac9" +
    "d300e6cfe19ea82c6316013f58e289a9" +
    "0d38341bab33ffb0bb480c5fb9b1cd2e" +
    "c5f3db47e5a59c770aa62068fe7fc1ad",
  "hex"
);

function expandKey(key: Uint8Array, effectiveKeyBits: number): Buffer {
  const expanded = Buffer.alloc(128);
  expanded.set(key);
  for (let index = key.byteLength; index < 128; index += 1) {
    expanded[index] = PI_TABLE.readUInt8(
      (expanded.readUInt8(index - 1) + expanded.readUInt8(index - key.byteLength)) & 0xff
    );
  }
  const effectiveBytes = Math.ceil(effectiveKeyBits / 8);
  const mask = 0xff >>> (8 * effectiveBytes - effectiveKeyBits);
  expanded[128 - effectiveBytes] = PI_TABLE.readUInt8(
    expanded.readUInt8(128 - effectiveBytes) & mask
  );
  for (let index = 127 - effectiveBytes; index >= 0; index -= 1) {
    expanded[index] = PI_TABLE.readUInt8(
      expanded.readUInt8(index + 1) ^ expanded.readUInt8(index + effectiveBytes)
    );
  }
  return expanded;
}

function rotateRight(value: number, count: number): number {
  return ((value >>> count) | (value << (16 - count))) & 0xffff;
}

/** Decrypts complete RC2-CBC blocks; the caller validates container padding. */
export function decryptRc2Cbc(
  encrypted: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  effectiveKeyBits: number
): Uint8Array {
  if (
    encrypted.byteLength === 0 ||
    encrypted.byteLength % 8 !== 0 ||
    key.byteLength < 1 ||
    key.byteLength > 128 ||
    iv.byteLength !== 8 ||
    !Number.isSafeInteger(effectiveKeyBits) ||
    effectiveKeyBits < 1 ||
    effectiveKeyBits > 1024
  ) {
    throw new Error("Invalid PKCS#12 RC2 parameters.");
  }
  const expanded = expandKey(key, effectiveKeyBits);
  const output = Buffer.from(encrypted);
  try {
    for (let offset = 0; offset < output.byteLength; offset += 8) {
      let r0 = output.readUInt16LE(offset);
      let r1 = output.readUInt16LE(offset + 2);
      let r2 = output.readUInt16LE(offset + 4);
      let r3 = output.readUInt16LE(offset + 6);
      let keyIndex = 63;
      for (let round = 0; round < 16; round += 1) {
        r3 =
          (rotateRight(r3, 5) - expanded.readUInt16LE(keyIndex-- * 2) - (r2 & r1) - (~r2 & r0)) &
          0xffff;
        r2 =
          (rotateRight(r2, 3) - expanded.readUInt16LE(keyIndex-- * 2) - (r1 & r0) - (~r1 & r3)) &
          0xffff;
        r1 =
          (rotateRight(r1, 2) - expanded.readUInt16LE(keyIndex-- * 2) - (r0 & r3) - (~r0 & r2)) &
          0xffff;
        r0 =
          (rotateRight(r0, 1) - expanded.readUInt16LE(keyIndex-- * 2) - (r3 & r2) - (~r3 & r1)) &
          0xffff;
        if (round === 4 || round === 10) {
          r3 = (r3 - expanded.readUInt16LE((r2 & 63) * 2)) & 0xffff;
          r2 = (r2 - expanded.readUInt16LE((r1 & 63) * 2)) & 0xffff;
          r1 = (r1 - expanded.readUInt16LE((r0 & 63) * 2)) & 0xffff;
          r0 = (r0 - expanded.readUInt16LE((r3 & 63) * 2)) & 0xffff;
        }
      }
      output.writeUInt16LE(r0, offset);
      output.writeUInt16LE(r1, offset + 2);
      output.writeUInt16LE(r2, offset + 4);
      output.writeUInt16LE(r3, offset + 6);
      const previous = offset === 0 ? iv : encrypted.subarray(offset - 8, offset);
      const previousBlock = new DataView(previous.buffer, previous.byteOffset, previous.byteLength);
      for (let index = 0; index < 8; index += 1) {
        output[offset + index] = output.readUInt8(offset + index) ^ previousBlock.getUint8(index);
      }
    }
    return output;
  } finally {
    expanded.fill(0);
  }
}
