import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createHash,
  createPublicKey,
  createSign,
  generateKeyPairSync,
  X509Certificate,
  type KeyObject,
} from "node:crypto";

import * as asn1js from "asn1js";
import {
  AlgorithmIdentifier,
  Attribute,
  Certificate,
  ContentInfo,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  SignedAndUnsignedAttributes,
  SignedData,
  SignerInfo,
} from "pkijs";

interface CertificateOptions {
  readonly commonName: string;
  readonly isCa: boolean;
  readonly issuerCertificate?: Certificate;
  readonly issuerKey?: KeyObject;
  readonly keyPair: { readonly privateKey: KeyObject; readonly publicKey: KeyObject };
  readonly serialNumber: number;
}

export interface SyntheticIdentity {
  readonly leafCertificate: Certificate;
  readonly leafKeys: { readonly privateKey: KeyObject; readonly publicKey: KeyObject };
  readonly unrelatedCertificate: Certificate;
  readonly unrelatedKeys: { readonly privateKey: KeyObject; readonly publicKey: KeyObject };
  readonly rootCertificate: Certificate;
  readonly rootKeys: { readonly privateKey: KeyObject; readonly publicKey: KeyObject };
}

export interface SyntheticIdentityOptions {
  readonly leafKeyBits?: number;
}

export interface Pkcs12Options {
  readonly certificateEncryption?: "none" | "pbe-sha1-3des";
  readonly includeMac?: boolean;
  readonly keyEncryption?: "none" | "pbe-sha1-3des";
  readonly macAlgorithm?: "sha1" | "sha256";
}

function keyPem(key: KeyObject): string {
  return key.export({ format: "pem", type: "pkcs8" }).toString();
}

function certificateFromPem(pem: string): Certificate {
  const body = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/gu, "");
  const der = Buffer.from(body, "base64");
  const parsed = asn1js.fromBER(Uint8Array.from(der).buffer);
  if (parsed.offset !== der.byteLength) {
    throw new Error("Synthetic certificate could not be decoded");
  }
  return new Certificate({ schema: parsed.result });
}

function certificatePemFromDer(certificate: Certificate): string {
  const der = Buffer.from(certificate.toSchema(true).toBER(false));
  const body =
    der
      .toString("base64")
      .match(/.{1,64}/gu)
      ?.join("\n") ?? "";
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

function makeCertificate(options: CertificateOptions): Certificate {
  const directory = mkdtempSync(join(tmpdir(), "udid-tools-cert-"));
  try {
    const keyPath = join(directory, "key.pem");
    const issuerKeyPath = join(directory, "issuer-key.pem");
    const issuerCertPath = join(directory, "issuer.pem");
    const outputPath = join(directory, "certificate.pem");
    const extensionPath = join(directory, "extensions.cnf");
    writeFileSync(keyPath, keyPem(options.keyPair.privateKey));
    writeFileSync(
      extensionPath,
      [
        "[v3_req]",
        `basicConstraints=critical,CA:${options.isCa ? "TRUE" : "FALSE"}`,
        options.isCa
          ? "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"
          : "keyUsage=critical,digitalSignature",
        "subjectKeyIdentifier=hash",
      ].join("\n")
    );

    if (options.issuerCertificate === undefined || options.issuerKey === undefined) {
      execFileSync(
        "openssl",
        [
          "req",
          "-new",
          "-x509",
          "-key",
          keyPath,
          "-out",
          outputPath,
          "-days",
          "365",
          "-sha256",
          "-set_serial",
          String(options.serialNumber),
          "-subj",
          `/CN=${options.commonName}`,
          "-addext",
          `basicConstraints=critical,CA:${options.isCa ? "TRUE" : "FALSE"}`,
          "-addext",
          options.isCa
            ? "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"
            : "keyUsage=critical,digitalSignature",
          "-addext",
          "subjectKeyIdentifier=hash",
        ],
        { stdio: "ignore" }
      );
    } else {
      writeFileSync(issuerKeyPath, keyPem(options.issuerKey));
      writeFileSync(issuerCertPath, certificatePemFromDer(options.issuerCertificate));
      const csrPath = join(directory, "certificate.csr");
      execFileSync(
        "openssl",
        ["req", "-new", "-key", keyPath, "-out", csrPath, "-subj", `/CN=${options.commonName}`],
        { stdio: "ignore" }
      );
      execFileSync(
        "openssl",
        [
          "x509",
          "-req",
          "-in",
          csrPath,
          "-CA",
          issuerCertPath,
          "-CAkey",
          issuerKeyPath,
          "-out",
          outputPath,
          "-days",
          "365",
          "-sha256",
          "-set_serial",
          String(options.serialNumber),
          "-extensions",
          "v3_req",
          "-extfile",
          extensionPath,
        ],
        { stdio: "ignore" }
      );
    }
    return certificateFromPem(readFileSync(outputPath, "utf8"));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export function createSyntheticIdentity(options: SyntheticIdentityOptions = {}): SyntheticIdentity {
  const rootKeys = generateKeyPairSync("rsa", { modulusLength: 2_048 });
  const rootCertificate = makeCertificate({
    commonName: "UDID Tools Synthetic Root",
    isCa: true,
    keyPair: rootKeys,
    serialNumber: 1,
  });
  const leafKeys = generateKeyPairSync("rsa", { modulusLength: options.leafKeyBits ?? 2_048 });
  const leafCertificate = makeCertificate({
    commonName: "UDID Tools Synthetic Signer",
    isCa: false,
    issuerCertificate: rootCertificate,
    issuerKey: rootKeys.privateKey,
    keyPair: leafKeys,
    serialNumber: 2,
  });
  const unrelatedKeys = generateKeyPairSync("rsa", { modulusLength: 2_048 });
  const unrelatedCertificate = makeCertificate({
    commonName: "UDID Tools Unrelated Certificate",
    isCa: true,
    keyPair: unrelatedKeys,
    serialNumber: 3,
  });
  return {
    leafCertificate,
    leafKeys,
    unrelatedCertificate,
    unrelatedKeys,
    rootCertificate,
    rootKeys,
  };
}

export function certificateDer(certificate: Certificate): Uint8Array {
  return Uint8Array.from(new Uint8Array(certificate.toSchema(true).toBER(false)));
}

export function certificatePem(certificate: Certificate): string {
  return certificatePemFromDer(certificate);
}

export function createPkcs12(
  privateKey: KeyObject | null,
  certificates: readonly Certificate[] | null,
  passphrase: string,
  options: Pkcs12Options = {}
): Uint8Array {
  const directory = mkdtempSync(join(tmpdir(), "udid-tools-p12-"));
  try {
    const keyPath = join(directory, "key.pem");
    const leafPath = join(directory, "leaf.pem");
    const chainPath = join(directory, "chain.pem");
    const passwordPath = join(directory, "password");
    const outputPath = join(directory, "identity.p12");
    writeFileSync(passwordPath, passphrase);
    if (privateKey !== null) {
      writeFileSync(keyPath, keyPem(privateKey));
    }
    if (certificates !== null && certificates.length > 0) {
      const matchingIndex =
        privateKey === null
          ? 0
          : certificates.findIndex((certificate) => {
              const certificatePublicKey = new X509Certificate(
                certificatePem(certificate)
              ).publicKey.export({ format: "der", type: "spki" });
              const privatePublicKey = createPublicKey(privateKey).export({
                format: "der",
                type: "spki",
              });
              return Buffer.from(certificatePublicKey).equals(Buffer.from(privatePublicKey));
            });
      const leafIndex = matchingIndex < 0 ? 0 : matchingIndex;
      writeFileSync(leafPath, certificatePem(certificates[leafIndex]!));
      if (certificates.length > 1) {
        writeFileSync(
          chainPath,
          certificates
            .filter((_, index) => index !== leafIndex)
            .map(certificatePem)
            .join("")
        );
      }
    }

    const args = [
      "pkcs12",
      "-export",
      "-out",
      outputPath,
      "-passout",
      `file:${passwordPath}`,
      "-keypbe",
      options.keyEncryption === "none" ? "NONE" : "PBE-SHA1-3DES",
      "-certpbe",
      options.certificateEncryption === "pbe-sha1-3des" ? "PBE-SHA1-3DES" : "NONE",
    ];
    if (options.includeMac === false) args.push("-nomac");
    else args.push("-macalg", options.macAlgorithm ?? "sha1");
    if (privateKey === null) args.push("-nokeys");
    else args.push("-inkey", keyPath);
    if (certificates === null || certificates.length === 0) args.push("-nocerts");
    else {
      args.push("-in", leafPath);
      if (certificates.length > 1) args.push("-certfile", chainPath);
    }
    execFileSync("openssl", args, { stdio: "ignore" });
    return Uint8Array.from(readFileSync(outputPath));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export function cloneCertificate(certificate: Certificate): Certificate {
  return Certificate.fromBER(Uint8Array.from(certificateDer(certificate)).buffer);
}

export function createCms(
  payload: Uint8Array,
  privateKey: KeyObject,
  signerCertificate: Certificate,
  embeddedCertificates: readonly Certificate[],
  options: {
    readonly detached?: boolean;
    readonly digestAlgorithm?: "sha1" | "sha256";
    readonly signerCount?: number;
  } = {}
): Uint8Array {
  const digestAlgorithm = options.digestAlgorithm ?? "sha256";
  const digestOid = digestAlgorithm === "sha1" ? "1.3.14.3.2.26" : "2.16.840.1.101.3.4.2.1";
  const signedData = new SignedData({
    certificates: [...embeddedCertificates],
    digestAlgorithms: [
      new AlgorithmIdentifier({ algorithmId: digestOid, algorithmParams: new asn1js.Null() }),
    ],
    encapContentInfo: new EncapsulatedContentInfo(
      options.detached === true
        ? { eContentType: "1.2.840.113549.1.7.1" }
        : {
            eContent: new asn1js.OctetString({ valueHex: Uint8Array.from(payload).buffer }),
            eContentType: "1.2.840.113549.1.7.1",
          }
    ),
    signerInfos: [],
    version: 1,
  });
  for (let index = 0; index < (options.signerCount ?? 1); index += 1) {
    const signedAttrs = new SignedAndUnsignedAttributes({
      attributes: [
        new Attribute({
          type: "1.2.840.113549.1.9.3",
          values: [new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.7.1" })],
        }),
        new Attribute({
          type: "1.2.840.113549.1.9.4",
          values: [
            new asn1js.OctetString({
              valueHex: createHash(digestAlgorithm).update(payload).digest(),
            }),
          ],
        }),
        new Attribute({
          type: "1.2.840.113549.1.9.5",
          values: [new asn1js.UTCTime({ valueDate: new Date() })],
        }),
      ],
      type: 0,
    });
    const attributesDer = Uint8Array.from(new Uint8Array(signedAttrs.toSchema().toBER(false)));
    attributesDer[0] = 0x31;
    const signer = createSign(digestAlgorithm === "sha1" ? "RSA-SHA1" : "RSA-SHA256");
    signer.update(attributesDer);
    signedData.signerInfos.push(
      new SignerInfo({
        digestAlgorithm: new AlgorithmIdentifier({
          algorithmId: digestOid,
          algorithmParams: new asn1js.Null(),
        }),
        sid: new IssuerAndSerialNumber({
          issuer: signerCertificate.issuer,
          serialNumber: signerCertificate.serialNumber,
        }),
        signature: new asn1js.OctetString({ valueHex: signer.sign(privateKey) }),
        signatureAlgorithm: new AlgorithmIdentifier({
          algorithmId: "1.2.840.113549.1.1.1",
          algorithmParams: new asn1js.Null(),
        }),
        signedAttrs,
        version: 1,
      })
    );
  }
  const contentInfo = new ContentInfo({
    content: signedData.toSchema(true),
    contentType: ContentInfo.SIGNED_DATA,
  });
  return Uint8Array.from(new Uint8Array(contentInfo.toSchema().toBER(false)));
}
