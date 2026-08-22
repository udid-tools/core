import forge from "node-forge";

interface CertificateOptions {
  readonly commonName: string;
  readonly isCa: boolean;
  readonly issuerCertificate?: forge.pki.Certificate;
  readonly issuerPrivateKey?: forge.pki.rsa.PrivateKey;
  readonly keyPair: forge.pki.rsa.KeyPair;
  readonly serialNumber: string;
}

export interface SyntheticIdentity {
  readonly leafCertificate: forge.pki.Certificate;
  readonly leafKeys: forge.pki.rsa.KeyPair;
  readonly unrelatedCertificate: forge.pki.Certificate;
  readonly unrelatedKeys: forge.pki.rsa.KeyPair;
  readonly rootCertificate: forge.pki.Certificate;
  readonly rootKeys: forge.pki.rsa.KeyPair;
}

export interface SyntheticIdentityOptions {
  readonly leafKeyBits?: number;
}

function makeCertificate(options: CertificateOptions): forge.pki.Certificate {
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = options.keyPair.publicKey;
  certificate.serialNumber = options.serialNumber;
  certificate.validity.notBefore = new Date(Date.now() - 24 * 60 * 60 * 1_000);
  certificate.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60 * 1_000);

  const subject = [{ name: "commonName", value: options.commonName }];
  certificate.setSubject(subject);
  certificate.setIssuer(options.issuerCertificate?.subject.attributes ?? subject);
  certificate.setExtensions([
    { cA: options.isCa, critical: true, name: "basicConstraints" },
    options.isCa
      ? {
          cRLSign: true,
          critical: true,
          digitalSignature: true,
          keyCertSign: true,
          name: "keyUsage",
        }
      : {
          critical: true,
          digitalSignature: true,
          name: "keyUsage",
        },
    { name: "subjectKeyIdentifier" },
  ]);

  certificate.sign(
    options.issuerPrivateKey ?? options.keyPair.privateKey,
    forge.md.sha256.create()
  );
  return certificate;
}

export function createSyntheticIdentity(options: SyntheticIdentityOptions = {}): SyntheticIdentity {
  // CA-only keys stay small to keep synthetic tests quick. The CMS signer uses
  // 2048 bits so tests exercise the library's production signing floor.
  const rootKeys = forge.pki.rsa.generateKeyPair(1_024);
  const rootCertificate = makeCertificate({
    commonName: "UDID Tools Synthetic Root",
    isCa: true,
    keyPair: rootKeys,
    serialNumber: "01",
  });

  const leafKeys = forge.pki.rsa.generateKeyPair(options.leafKeyBits ?? 2_048);
  const leafCertificate = makeCertificate({
    commonName: "UDID Tools Synthetic Signer",
    isCa: false,
    issuerCertificate: rootCertificate,
    issuerPrivateKey: rootKeys.privateKey,
    keyPair: leafKeys,
    serialNumber: "02",
  });

  const unrelatedKeys = forge.pki.rsa.generateKeyPair(1_024);
  const unrelatedCertificate = makeCertificate({
    commonName: "UDID Tools Unrelated Certificate",
    isCa: true,
    keyPair: unrelatedKeys,
    serialNumber: "03",
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

export function certificateDer(certificate: forge.pki.Certificate): Uint8Array {
  const bytes = forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes();
  return Uint8Array.from(forge.util.binary.raw.decode(bytes));
}

export function certificatePem(certificate: forge.pki.Certificate): string {
  return forge.pki.certificateToPem(certificate);
}

export function createPkcs12(
  privateKey: forge.pki.rsa.PrivateKey | null,
  certificates: readonly forge.pki.Certificate[] | null,
  passphrase: string
): Uint8Array {
  // node-forge explicitly handles a null certificate argument at runtime for
  // key-only PKCS#12 files, but the DefinitelyTyped declaration omits null.
  const forgeCertificates =
    certificates === null ? (null as unknown as forge.pki.Certificate[]) : [...certificates];
  const asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, forgeCertificates, passphrase, {
    algorithm: "3des",
  });
  return Uint8Array.from(forge.util.binary.raw.decode(forge.asn1.toDer(asn1).getBytes()));
}
