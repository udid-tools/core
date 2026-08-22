import type { ResourceLimitsInput } from "./limits.js";

/** Scalar values supported by the XML property-list codec. */
export type PlistPrimitive = boolean | Date | number | string | Uint8Array;
/** A lossless property-list dictionary. Decoded dictionaries have a null prototype. */
export interface PlistDictionary {
  readonly [key: string]: PlistValue;
}
/** Any value representable by the library's bounded XML property-list codec. */
export type PlistValue = PlistPrimitive | readonly PlistValue[] | PlistDictionary;

/** A textual binary container with an explicit, strict decoding rule. */
export interface EncodedBinaryInput {
  readonly encoding: "base64" | "pem";
  readonly value: string;
}

/** Binary bytes or their explicit base64/PEM representation. */
export type BinaryInput = EncodedBinaryInput | Uint8Array;
/** X.509 certificate input in DER bytes, canonical base64, or PEM. */
export type CertificateInput = BinaryInput;

/** Attribute names documented across Apple's Profile Service examples. */
export const KNOWN_DEVICE_ATTRIBUTES = Object.freeze([
  "UDID",
  "VERSION",
  "PRODUCT",
  "SERIAL",
  "IMEI",
  "MEID",
  "ICCID",
  "MAC_ADDRESS_EN0",
] as const);

/** A device attribute currently normalized by the public response API. */
export type KnownDeviceAttribute = (typeof KNOWN_DEVICE_ATTRIBUTES)[number];

declare const customDeviceAttributeBrand: unique symbol;
/** Deliberately opted-in, forward-compatible uppercase device attribute. */
export type CustomDeviceAttribute = string & {
  readonly [customDeviceAttributeBrand]: true;
};

/** A known or explicitly branded custom Profile Service attribute name. */
export type DeviceAttribute = CustomDeviceAttribute | KnownDeviceAttribute;

/** Opaque correlation value included in the request profile and device response. */
export type ProfileServiceChallenge =
  | {
      readonly type: "data";
      readonly value: Uint8Array;
    }
  | {
      readonly type: "string";
      readonly value: string;
    };

/** Complete typed definition of Apple's special `Profile Service` profile. */
export interface ProfileServiceDefinition {
  readonly kind: "profile-service";
  readonly description?: string;
  readonly displayName: string;
  /** Additional top-level fields retained for forwards compatibility. */
  readonly extensions?: Readonly<Record<string, PlistValue>>;
  readonly identifier: string;
  readonly organization?: string;
  readonly service: {
    readonly challenge?: ProfileServiceChallenge;
    readonly deviceAttributes: readonly DeviceAttribute[];
    readonly extensions?: Readonly<Record<string, PlistValue>>;
    readonly responseUrl: string;
  };
  readonly uuid?: string;
}

/** PKCS#12/PFX signing identity supported by the beta cryptographic profile. */
export interface Pkcs12SigningIdentity {
  readonly data: BinaryInput;
  readonly passphrase?: string;
  readonly type: "pkcs12";
}

/** Optional signing configuration. Its presence requests signed output. */
export interface SigningOptions {
  readonly certificateChain?: readonly CertificateInput[];
  readonly digestAlgorithm?: "sha256";
  readonly identity: Pkcs12SigningIdentity;
}

/** Input to {@link generateProfile}. */
export interface ProfileGenerationOptions {
  readonly limits?: ResourceLimitsInput;
  readonly profile: ProfileServiceDefinition;
  readonly signing?: SigningOptions;
}

/** Generated XML or CMS profile bytes and format metadata. */
export interface GeneratedProfile {
  readonly contentType: "application/x-apple-aspen-config";
  readonly data: Uint8Array;
  readonly profile: {
    readonly identifier: string;
    readonly kind: "profile-service";
    readonly uuid: string;
  };
  readonly protection: {
    readonly encrypted: false;
    readonly signed: boolean;
  };
}

/** Sanitized public metadata for an embedded CMS signer certificate. */
export interface CertificateInfo {
  readonly issuer: string;
  readonly notAfter: Date;
  readonly notBefore: Date;
  readonly serialNumber: string;
  readonly sha256Fingerprint: string;
  readonly subject: string;
}

/** Explicit response verification policy; no system trust is used. */
export type ResponseVerificationOptions =
  | { readonly mode: "none" }
  | { readonly mode: "signature" }
  | {
      readonly intermediates?: readonly CertificateInput[];
      readonly mode: "trust-chain";
      readonly trustAnchors: readonly CertificateInput[];
    };

/** Controls response acceptance, correlation, normalization, and resource limits. */
export interface ParseProfileServiceResponseOptions {
  readonly allowUnsigned?: boolean;
  readonly expectedAttributes?: readonly KnownDeviceAttribute[];
  readonly expectedChallenge?: ProfileServiceChallenge;
  readonly limits?: ResourceLimitsInput;
  readonly requiredAttributes?: readonly KnownDeviceAttribute[];
  readonly verification?: ResponseVerificationOptions;
}

/** Raw CMS/XML input accepted by the response parser. */
export type ProfileServiceResponseInput = ArrayBuffer | string | Uint8Array;

/** Known Apple response fields normalized to JavaScript naming. */
export interface ProfileServiceAttributes {
  readonly iccid?: string;
  readonly imei?: string;
  readonly macAddressEn0?: string;
  readonly meid?: string;
  readonly product?: string;
  readonly serialNumber?: string;
  readonly udid?: string;
  readonly version?: string;
}

/** Verified and decoded Apple Profile Service device response. */
export interface ProfileServiceResponse {
  readonly attributes: ProfileServiceAttributes;
  readonly challenge?: string | Uint8Array;
  readonly raw: Readonly<Record<string, PlistValue>>;
  readonly signature: {
    readonly present: boolean;
    readonly signers: readonly CertificateInfo[];
    readonly trusted: boolean | null;
    readonly valid: boolean | null;
  };
}
