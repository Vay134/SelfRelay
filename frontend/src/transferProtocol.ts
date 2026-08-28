/**
 * Version 1 of the browser-to-browser cryptographic transfer protocol.
 *
 * This module deliberately keeps the protocol primitives independent from the
 * UI and transport layers.  It is safe to use from tests with Web Crypto's
 * implementation and from the browser runtime without a third-party crypto
 * dependency.
 */

export const TRANSFER_PROTOCOL_VERSION = 1 as const;
export const TRANSCRIPT_DOMAIN = 'secure-transfer/v1/transcript';
export const KEY_DERIVATION_DOMAIN = 'secure-transfer/v1/';
export const MAX_HANDSHAKE_MESSAGE_BYTES = 16 * 1024;
export const SHA256_BYTES = 32;
export const P256_SIGNATURE_BYTES = 64;

export type ByteInput = Uint8Array | ArrayBuffer | ArrayBufferView;

export class ProtocolError extends Error {
    readonly code: string;

    constructor(message: string, code = 'protocol_error') {
        super(message);
        this.name = 'ProtocolError';
        this.code = code;
    }
}

function cryptoProvider(): Crypto {
    const available = globalThis.crypto;
    if (!available?.subtle || typeof available.getRandomValues !== 'function') {
        throw new ProtocolError('Web Crypto is unavailable.', 'crypto_unavailable');
    }
    return available;
}

export function copyBytes(value: ByteInput): Uint8Array {
    if (value instanceof Uint8Array) {
        return new Uint8Array(value);
    }
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value.slice(0));
    }
    return new Uint8Array(
        value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength),
    );
}

function asBufferSource(value: ByteInput): ArrayBuffer {
    const bytes = copyBytes(value);
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function equalBytes(left: ByteInput, right: ByteInput): boolean {
    const leftBytes = copyBytes(left);
    const rightBytes = copyBytes(right);
    if (leftBytes.byteLength !== rightBytes.byteLength) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < leftBytes.byteLength; index += 1) {
        difference |= leftBytes[index] ^ rightBytes[index];
    }
    return difference === 0;
}

/** Encode bytes as unpadded base64url. */
export function encodeBase64Url(value: ByteInput): string {
    const bytes = copyBytes(value);
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, '');
}

/** Decode only canonical, unpadded base64url. */
export function decodeBase64Url(value: string, maximumBytes = 16 * 1024): Uint8Array {
    if (typeof value !== 'string' || value.length > maximumBytes * 2) {
        throw new ProtocolError('Invalid base64url value.', 'invalid_base64url');
    }
    if (!/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) {
        throw new ProtocolError('Invalid base64url value.', 'invalid_base64url');
    }
    if (value.length === 0) {
        return new Uint8Array();
    }
    const padding = '='.repeat((4 - (value.length % 4)) % 4);
    let binary: string;
    try {
        binary = atob(value.replace(/-/gu, '+').replace(/_/gu, '/') + padding);
    } catch {
        throw new ProtocolError('Invalid base64url value.', 'invalid_base64url');
    }
    const result = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (result.byteLength > maximumBytes || encodeBase64Url(result) !== value) {
        throw new ProtocolError('Invalid base64url value.', 'invalid_base64url');
    }
    return result;
}

function compareUtf16(left: string, right: string): number {
    if (left < right) {
        return -1;
    }
    if (left > right) {
        return 1;
    }
    return 0;
}

function canonicalJsonValue(value: unknown, seen: Set<object>): string {
    if (value === null) {
        return 'null';
    }
    if (typeof value === 'string') {
        return JSON.stringify(value);
    }
    if (typeof value === 'boolean') {
        return value ? 'true' : 'false';
    }
    if (typeof value === 'number') {
        if (!Number.isFinite(value)) {
            throw new ProtocolError(
                'Canonical JSON does not support non-finite numbers.',
                'invalid_json',
            );
        }
        const encoded = JSON.stringify(value);
        if (encoded === undefined) {
            throw new ProtocolError('Canonical JSON number is invalid.', 'invalid_json');
        }
        return encoded;
    }
    if (
        typeof value === 'bigint' ||
        typeof value === 'undefined' ||
        typeof value === 'function' ||
        typeof value === 'symbol'
    ) {
        throw new ProtocolError('Canonical JSON does not support this value.', 'invalid_json');
    }
    if (typeof value !== 'object') {
        throw new ProtocolError('Canonical JSON does not support this value.', 'invalid_json');
    }
    if (seen.has(value)) {
        throw new ProtocolError('Canonical JSON cannot contain cycles.', 'invalid_json');
    }
    seen.add(value);
    let encoded: string;
    if (Array.isArray(value)) {
        encoded = `[${value.map((item) => canonicalJsonValue(item, seen)).join(',')}]`;
    } else {
        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null) {
            throw new ProtocolError('Canonical JSON requires plain objects.', 'invalid_json');
        }
        if (Object.getOwnPropertySymbols(value).length > 0) {
            throw new ProtocolError('Canonical JSON object keys must be strings.', 'invalid_json');
        }
        const entries = Object.keys(value)
            .sort(compareUtf16)
            .map(
                (key) =>
                    `${JSON.stringify(key)}:${canonicalJsonValue((value as Record<string, unknown>)[key], seen)}`,
            );
        encoded = `{${entries.join(',')}}`;
    }
    seen.delete(value);
    return encoded;
}

/** Serialize a JSON value according to RFC 8785 property ordering. */
export function canonicalJson(value: unknown): string {
    return canonicalJsonValue(value, new Set<object>());
}

export function canonicalJsonBytes(value: unknown): Uint8Array {
    return new TextEncoder().encode(canonicalJson(value));
}

export function canonicalizeJson(value: unknown): Uint8Array {
    return canonicalJsonBytes(value);
}

function decodeUtf8(value: ByteInput): string {
    try {
        return new TextDecoder('utf-8', { fatal: true }).decode(copyBytes(value));
    } catch {
        throw new ProtocolError('JSON must contain valid UTF-8.', 'invalid_json');
    }
}

function skipWhitespace(value: string, index: number): number {
    while (
        index < value.length &&
        (value.charCodeAt(index) === 9 ||
            value.charCodeAt(index) === 10 ||
            value.charCodeAt(index) === 13 ||
            value.charCodeAt(index) === 32)
    ) {
        index += 1;
    }
    return index;
}

function scanJsonString(value: string, start: number): number {
    let index = start + 1;
    while (index < value.length) {
        const character = value[index];
        if (character === '"') {
            return index + 1;
        }
        if (character < ' ') {
            throw new ProtocolError('JSON string contains a control character.', 'invalid_json');
        }
        if (character === '\\') {
            index += 1;
            if (index >= value.length) {
                throw new ProtocolError('JSON string escape is truncated.', 'invalid_json');
            }
            const escape = value[index];
            if (escape === 'u') {
                if (!/^[0-9a-fA-F]{4}$/u.test(value.slice(index + 1, index + 5))) {
                    throw new ProtocolError('JSON unicode escape is invalid.', 'invalid_json');
                }
                index += 4;
            } else if (!'"\\/bfnrt'.includes(escape)) {
                throw new ProtocolError('JSON string escape is invalid.', 'invalid_json');
            }
        }
        index += 1;
    }
    throw new ProtocolError('JSON string is unterminated.', 'invalid_json');
}

function scanJsonValue(value: string, start: number): number {
    const index = skipWhitespace(value, start);
    const character = value[index];
    if (character === '"') {
        return scanJsonString(value, index);
    }
    if (character === '[') {
        let cursor = skipWhitespace(value, index + 1);
        if (value[cursor] === ']') {
            return cursor + 1;
        }
        while (true) {
            cursor = scanJsonValue(value, cursor);
            cursor = skipWhitespace(value, cursor);
            if (value[cursor] === ']') {
                return cursor + 1;
            }
            if (value[cursor] !== ',') {
                throw new ProtocolError('JSON array separator is invalid.', 'invalid_json');
            }
            cursor = skipWhitespace(value, cursor + 1);
            if (value[cursor] === ']') {
                throw new ProtocolError('JSON array has a trailing comma.', 'invalid_json');
            }
        }
    }
    if (character === '{') {
        const keys = new Set<string>();
        let cursor = skipWhitespace(value, index + 1);
        if (value[cursor] === '}') {
            return cursor + 1;
        }
        while (true) {
            if (value[cursor] !== '"') {
                throw new ProtocolError('JSON object key is invalid.', 'invalid_json');
            }
            const keyEnd = scanJsonString(value, cursor);
            let key: unknown;
            try {
                key = JSON.parse(value.slice(cursor, keyEnd)) as unknown;
            } catch {
                throw new ProtocolError('JSON object key is invalid.', 'invalid_json');
            }
            if (typeof key !== 'string' || keys.has(key)) {
                throw new ProtocolError(
                    'JSON object contains duplicate keys.',
                    'duplicate_json_key',
                );
            }
            keys.add(key);
            cursor = skipWhitespace(value, keyEnd);
            if (value[cursor] !== ':') {
                throw new ProtocolError('JSON object separator is invalid.', 'invalid_json');
            }
            cursor = scanJsonValue(value, cursor + 1);
            cursor = skipWhitespace(value, cursor);
            if (value[cursor] === '}') {
                return cursor + 1;
            }
            if (value[cursor] !== ',') {
                throw new ProtocolError('JSON object separator is invalid.', 'invalid_json');
            }
            cursor = skipWhitespace(value, cursor + 1);
            if (value[cursor] === '}') {
                throw new ProtocolError('JSON object has a trailing comma.', 'invalid_json');
            }
        }
    }
    if (value.startsWith('true', index)) {
        return index + 4;
    }
    if (value.startsWith('false', index)) {
        return index + 5;
    }
    if (value.startsWith('null', index)) {
        return index + 4;
    }
    const number = value.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u)?.[0];
    if (number) {
        return index + number.length;
    }
    throw new ProtocolError('JSON value is invalid.', 'invalid_json');
}

/** Parse JSON while rejecting duplicate object keys. */
export function parseStrictJson(value: string | ByteInput): unknown {
    const text = typeof value === 'string' ? value : decodeUtf8(value);
    if (text.startsWith('\uFEFF')) {
        throw new ProtocolError('JSON must not contain a byte-order mark.', 'invalid_json');
    }
    const end = skipWhitespace(text, scanJsonValue(text, 0));
    if (end !== text.length) {
        throw new ProtocolError('JSON contains trailing data.', 'invalid_json');
    }
    try {
        return JSON.parse(text) as unknown;
    } catch {
        throw new ProtocolError('JSON value is invalid.', 'invalid_json');
    }
}

/** Parse JSON and require its bytes to already be RFC 8785 canonical. */
export function parseCanonicalJson(value: string | ByteInput): unknown {
    const raw = typeof value === 'string' ? new TextEncoder().encode(value) : copyBytes(value);
    const parsed = parseStrictJson(raw);
    if (!equalBytes(raw, canonicalJsonBytes(parsed))) {
        throw new ProtocolError('Signed JSON is not canonical.', 'non_canonical_json');
    }
    return parsed;
}

function requireP256KeyAlgorithm(purpose: 'signing' | 'agreement'): EcKeyImportParams {
    return {
        name: purpose === 'signing' ? 'ECDSA' : 'ECDH',
        namedCurve: 'P-256',
    };
}

/** Export a public key as DER SubjectPublicKeyInfo. */
export async function exportSpki(publicKey: CryptoKey): Promise<Uint8Array> {
    try {
        return copyBytes(await cryptoProvider().subtle.exportKey('spki', publicKey));
    } catch {
        throw new ProtocolError('Unable to export the P-256 public key.', 'invalid_public_key');
    }
}

/** Import a canonical P-256 SPKI for signature verification or ECDH. */
export async function importP256Spki(
    publicKeySpki: ByteInput,
    purpose: 'signing' | 'agreement' = 'signing',
): Promise<CryptoKey> {
    const raw = copyBytes(publicKeySpki);
    if (raw.byteLength < 1 || raw.byteLength > 1024) {
        throw new ProtocolError(
            'The P-256 public key has an invalid length.',
            'invalid_public_key',
        );
    }
    const usages: KeyUsage[] = purpose === 'signing' ? ['verify'] : [];
    let key: CryptoKey;
    try {
        key = await cryptoProvider().subtle.importKey(
            'spki',
            asBufferSource(raw),
            requireP256KeyAlgorithm(purpose),
            true,
            usages,
        );
        const exported = await cryptoProvider().subtle.exportKey('spki', key);
        if (!equalBytes(raw, exported)) {
            throw new ProtocolError(
                'The P-256 public key is not canonical SPKI.',
                'invalid_public_key',
            );
        }
    } catch (error) {
        if (error instanceof ProtocolError) {
            throw error;
        }
        throw new ProtocolError('The P-256 public key is invalid.', 'invalid_public_key');
    }
    return key;
}

export const importSpki = importP256Spki;

/** SHA-256 fingerprint of the exact DER SPKI bytes. */
export async function fingerprintSpki(publicKeySpki: ByteInput): Promise<string> {
    try {
        const digest = await cryptoProvider().subtle.digest(
            'SHA-256',
            asBufferSource(publicKeySpki),
        );
        return encodeBase64Url(digest);
    } catch {
        throw new ProtocolError('Unable to fingerprint the public key.', 'invalid_public_key');
    }
}

export async function generateP256SigningKeyPair(extractable = false): Promise<CryptoKeyPair> {
    try {
        return (await cryptoProvider().subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            extractable,
            ['sign', 'verify'],
        )) as CryptoKeyPair;
    } catch {
        throw new ProtocolError('Unable to generate a P-256 signing key.', 'crypto_failure');
    }
}

export async function generateP256AgreementKeyPair(extractable = false): Promise<CryptoKeyPair> {
    try {
        return (await cryptoProvider().subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            extractable,
            ['deriveBits'],
        )) as CryptoKeyPair;
    } catch {
        throw new ProtocolError('Unable to generate a P-256 agreement key.', 'crypto_failure');
    }
}

function derLength(length: number): Uint8Array {
    if (length < 0 || length > 127) {
        if (length > 255) {
            throw new ProtocolError('ECDSA signature is too long.', 'invalid_signature');
        }
        return new Uint8Array([0x81, length]);
    }
    return new Uint8Array([length]);
}

function derInteger(value: Uint8Array): Uint8Array {
    let start = 0;
    while (start < value.byteLength - 1 && value[start] === 0) {
        start += 1;
    }
    let body = value.slice(start);
    if ((body[0] & 0x80) !== 0) {
        body = Uint8Array.of(0, ...body);
    }
    return Uint8Array.of(0x02, ...derLength(body.byteLength), ...body);
}

/** Convert a fixed-width 64-byte P1363 signature to strict DER. */
export function p1363ToDer(signature: ByteInput): Uint8Array {
    const bytes = copyBytes(signature);
    if (bytes.byteLength !== P256_SIGNATURE_BYTES) {
        throw new ProtocolError('ECDSA signature must be 64-byte P1363.', 'invalid_signature');
    }
    if (
        bytes.slice(0, 32).every((byte) => byte === 0) ||
        bytes.slice(32).every((byte) => byte === 0)
    ) {
        throw new ProtocolError('ECDSA signature integers must be positive.', 'invalid_signature');
    }
    const body = Uint8Array.of(...derInteger(bytes.slice(0, 32)), ...derInteger(bytes.slice(32)));
    return Uint8Array.of(0x30, ...derLength(body.byteLength), ...body);
}

function readDerLength(bytes: Uint8Array, offset: number): { length: number; next: number } {
    const first = bytes[offset];
    if (first === undefined) {
        throw new ProtocolError('DER length is truncated.', 'invalid_signature');
    }
    if ((first & 0x80) === 0) {
        return { length: first, next: offset + 1 };
    }
    const count = first & 0x7f;
    if (count !== 1 || bytes[offset + 1] === undefined || bytes[offset + 1] < 128) {
        throw new ProtocolError('DER length is not canonical.', 'invalid_signature');
    }
    return { length: bytes[offset + 1], next: offset + 2 };
}

function readDerInteger(bytes: Uint8Array, offset: number): { value: Uint8Array; next: number } {
    if (bytes[offset] !== 0x02) {
        throw new ProtocolError('DER signature integer is invalid.', 'invalid_signature');
    }
    const length = readDerLength(bytes, offset + 1);
    const end = length.next + length.length;
    if (length.length < 1 || end > bytes.byteLength) {
        throw new ProtocolError('DER signature integer is truncated.', 'invalid_signature');
    }
    const value = bytes.slice(length.next, end);
    if (
        (value[0] & 0x80) !== 0 ||
        (value.length > 1 && value[0] === 0 && (value[1] & 0x80) === 0)
    ) {
        throw new ProtocolError(
            'DER signature integer is not minimally encoded.',
            'invalid_signature',
        );
    }
    if (
        value.every((byte) => byte === 0) ||
        value.length > 33 ||
        (value.length === 33 && value[0] !== 0)
    ) {
        throw new ProtocolError('DER signature integer is out of range.', 'invalid_signature');
    }
    return { value, next: end };
}

/** Convert a strict DER ECDSA signature to fixed-width P1363. */
export function derToP1363(signature: ByteInput): Uint8Array {
    const bytes = copyBytes(signature);
    if (bytes[0] !== 0x30) {
        throw new ProtocolError('DER ECDSA signature is invalid.', 'invalid_signature');
    }
    const sequenceLength = readDerLength(bytes, 1);
    const sequenceEnd = sequenceLength.next + sequenceLength.length;
    if (sequenceEnd !== bytes.byteLength) {
        throw new ProtocolError('DER ECDSA signature has trailing data.', 'invalid_signature');
    }
    const r = readDerInteger(bytes, sequenceLength.next);
    const s = readDerInteger(bytes, r.next);
    if (s.next !== sequenceEnd) {
        throw new ProtocolError('DER ECDSA signature has extra values.', 'invalid_signature');
    }
    const normalize = (value: Uint8Array): Uint8Array => {
        const withoutSign = value[0] === 0 ? value.slice(1) : value;
        if (withoutSign.byteLength > 32 || withoutSign.every((byte) => byte === 0)) {
            throw new ProtocolError(
                'ECDSA signature integer is out of range.',
                'invalid_signature',
            );
        }
        const output = new Uint8Array(32);
        output.set(withoutSign, 32 - withoutSign.byteLength);
        return output;
    };
    return Uint8Array.of(...normalize(r.value), ...normalize(s.value));
}

export const p1363ToDER = p1363ToDer;
export const derToP1363Signature = derToP1363;

export function normalizeP1363Signature(signature: ByteInput): Uint8Array {
    const bytes = copyBytes(signature);
    return bytes.byteLength === P256_SIGNATURE_BYTES ? bytes : derToP1363(bytes);
}

export async function signP256(privateKey: CryptoKey, message: ByteInput): Promise<Uint8Array> {
    try {
        const signature = await cryptoProvider().subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            privateKey,
            asBufferSource(message),
        );
        return normalizeP1363Signature(signature);
    } catch {
        throw new ProtocolError('Unable to create the ECDSA signature.', 'crypto_failure');
    }
}

export async function verifyP256(
    publicKey: CryptoKey,
    message: ByteInput,
    signature: ByteInput,
): Promise<boolean> {
    try {
        const p1363 = copyBytes(signature);
        if (p1363.byteLength !== P256_SIGNATURE_BYTES) {
            return false;
        }
        return await cryptoProvider().subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            publicKey,
            asBufferSource(p1363),
            asBufferSource(message),
        );
    } catch {
        return false;
    }
}

export function randomBytes(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0 || length > 65536) {
        throw new ProtocolError('Random byte length is invalid.', 'invalid_length');
    }
    const bytes = new Uint8Array(length);
    if (length > 0) {
        cryptoProvider().getRandomValues(bytes);
    }
    return bytes;
}

export async function sha256(value: ByteInput): Promise<Uint8Array> {
    try {
        return copyBytes(await cryptoProvider().subtle.digest('SHA-256', asBufferSource(value)));
    } catch {
        throw new ProtocolError('Unable to calculate SHA-256.', 'crypto_failure');
    }
}

export type HandshakeOfferCore = {
    v: typeof TRANSFER_PROTOCOL_VERSION;
    type: 'handshake_offer';
    transfer_id: string;
    account_epoch: number;
    sender_device_id: string;
    recipient_device_id: string;
    sender_ephemeral_spki: string;
    sender_nonce: string;
    issued_at: number;
    expires_at: number;
};

export type HandshakeAnswerCore = {
    v: typeof TRANSFER_PROTOCOL_VERSION;
    type: 'handshake_answer';
    transfer_id: string;
    account_epoch: number;
    sender_device_id: string;
    recipient_device_id: string;
    offer_hash: string;
    recipient_ephemeral_spki: string;
    recipient_nonce: string;
    issued_at: number;
    expires_at: number;
};

export type SignedHandshakeOffer = {
    core: HandshakeOfferCore;
    signature: string;
};

export type SignedHandshakeAnswer = {
    core: HandshakeAnswerCore;
    signature: string;
};

type SignedMessageOptions = {
    transferId: string;
    accountEpoch: number;
    senderDeviceId: string;
    recipientDeviceId: string;
    issuedAt?: number;
    expiresAt: number;
    nonce?: ByteInput;
    signingKey: CryptoKey;
    ephemeralKeyPair?: CryptoKeyPair;
};

export type HandshakeOfferOptions = SignedMessageOptions;

export type HandshakeAnswerOptions = Omit<SignedMessageOptions, 'nonce'> & {
    offer: SignedHandshakeOffer | HandshakeOfferCore;
    nonce?: ByteInput;
};

export type HandshakeExpectations = {
    transferId?: string;
    accountEpoch?: number;
    senderDeviceId?: string;
    recipientDeviceId?: string;
    now?: number;
};

export type HandshakeAnswerExpectations = HandshakeExpectations & {
    offer: SignedHandshakeOffer | HandshakeOfferCore;
};

export type HandshakeOfferResult = SignedHandshakeOffer & {
    ephemeralKeyPair: CryptoKeyPair;
};

export type HandshakeAnswerResult = SignedHandshakeAnswer & {
    ephemeralKeyPair: CryptoKeyPair;
};

function isPlainRecord(value: unknown): value is Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function requireSafeInteger(value: unknown, name: string, minimum = 0): number {
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) {
        throw new ProtocolError(`${name} must be a safe integer.`, 'invalid_handshake');
    }
    return value;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function requireUuid(value: unknown, name: string): string {
    if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
        throw new ProtocolError(`${name} must be a lowercase UUID.`, 'invalid_handshake');
    }
    return value;
}

function requireFixedBase64(value: unknown, name: string, length: number): string {
    if (typeof value !== 'string') {
        throw new ProtocolError(`${name} must be base64url.`, 'invalid_handshake');
    }
    const bytes = decodeBase64Url(value, Math.max(length, 1024));
    if (bytes.byteLength !== length) {
        throw new ProtocolError(`${name} has an invalid length.`, 'invalid_handshake');
    }
    return value;
}

function requireSpkiBase64(value: unknown, name: string): string {
    if (typeof value !== 'string') {
        throw new ProtocolError(`${name} must be base64url.`, 'invalid_handshake');
    }
    const bytes = decodeBase64Url(value, 1024);
    if (bytes.byteLength < 1 || bytes.byteLength > 1024) {
        throw new ProtocolError(`${name} has an invalid length.`, 'invalid_handshake');
    }
    return value;
}

function requireExactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
    const expected = new Set(keys);
    for (const key of Object.keys(value)) {
        if (!expected.has(key)) {
            throw new ProtocolError(
                `Signed message contains an unknown field: ${key}.`,
                'extra_field',
            );
        }
    }
    for (const key of keys) {
        if (!Object.prototype.hasOwnProperty.call(value, key)) {
            throw new ProtocolError(`Signed message is missing field: ${key}.`, 'missing_field');
        }
    }
}

const OFFER_KEYS = [
    'v',
    'type',
    'transfer_id',
    'account_epoch',
    'sender_device_id',
    'recipient_device_id',
    'sender_ephemeral_spki',
    'sender_nonce',
    'issued_at',
    'expires_at',
] as const;

const ANSWER_KEYS = [
    'v',
    'type',
    'transfer_id',
    'account_epoch',
    'sender_device_id',
    'recipient_device_id',
    'offer_hash',
    'recipient_ephemeral_spki',
    'recipient_nonce',
    'issued_at',
    'expires_at',
] as const;

function validateExpiry(issuedAt: number, expiresAt: number, now: number): void {
    if (expiresAt <= issuedAt || expiresAt <= now) {
        throw new ProtocolError('Handshake message has expired.', 'expired_handshake');
    }
}

export function validateHandshakeOfferCore(value: unknown, now = Date.now()): HandshakeOfferCore {
    if (!isPlainRecord(value)) {
        throw new ProtocolError('Handshake offer must be an object.', 'invalid_handshake');
    }
    requireExactKeys(value, OFFER_KEYS);
    if (value.v !== TRANSFER_PROTOCOL_VERSION || value.type !== 'handshake_offer') {
        throw new ProtocolError(
            'Handshake offer version or type is unsupported.',
            'unsupported_version',
        );
    }
    const issuedAt = requireSafeInteger(value.issued_at, 'issued_at');
    const expiresAt = requireSafeInteger(value.expires_at, 'expires_at');
    validateExpiry(issuedAt, expiresAt, now);
    return {
        v: TRANSFER_PROTOCOL_VERSION,
        type: 'handshake_offer',
        transfer_id: requireUuid(value.transfer_id, 'transfer_id'),
        account_epoch: requireSafeInteger(value.account_epoch, 'account_epoch'),
        sender_device_id: requireUuid(value.sender_device_id, 'sender_device_id'),
        recipient_device_id: requireUuid(value.recipient_device_id, 'recipient_device_id'),
        sender_ephemeral_spki: requireSpkiBase64(
            value.sender_ephemeral_spki,
            'sender_ephemeral_spki',
        ),
        sender_nonce: requireFixedBase64(value.sender_nonce, 'sender_nonce', 32),
        issued_at: issuedAt,
        expires_at: expiresAt,
    };
}

export function validateHandshakeAnswerCore(value: unknown, now = Date.now()): HandshakeAnswerCore {
    if (!isPlainRecord(value)) {
        throw new ProtocolError('Handshake answer must be an object.', 'invalid_handshake');
    }
    requireExactKeys(value, ANSWER_KEYS);
    if (value.v !== TRANSFER_PROTOCOL_VERSION || value.type !== 'handshake_answer') {
        throw new ProtocolError(
            'Handshake answer version or type is unsupported.',
            'unsupported_version',
        );
    }
    const issuedAt = requireSafeInteger(value.issued_at, 'issued_at');
    const expiresAt = requireSafeInteger(value.expires_at, 'expires_at');
    validateExpiry(issuedAt, expiresAt, now);
    return {
        v: TRANSFER_PROTOCOL_VERSION,
        type: 'handshake_answer',
        transfer_id: requireUuid(value.transfer_id, 'transfer_id'),
        account_epoch: requireSafeInteger(value.account_epoch, 'account_epoch'),
        sender_device_id: requireUuid(value.sender_device_id, 'sender_device_id'),
        recipient_device_id: requireUuid(value.recipient_device_id, 'recipient_device_id'),
        offer_hash: requireFixedBase64(value.offer_hash, 'offer_hash', SHA256_BYTES),
        recipient_ephemeral_spki: requireSpkiBase64(
            value.recipient_ephemeral_spki,
            'recipient_ephemeral_spki',
        ),
        recipient_nonce: requireFixedBase64(value.recipient_nonce, 'recipient_nonce', 32),
        issued_at: issuedAt,
        expires_at: expiresAt,
    };
}

function signedWrapper(value: unknown): { core: unknown; signature: string } {
    if (!isPlainRecord(value)) {
        throw new ProtocolError('Signed handshake message must be an object.', 'invalid_handshake');
    }
    requireExactKeys(value, ['core', 'signature']);
    if (typeof value.signature !== 'string') {
        throw new ProtocolError('Handshake signature must be base64url.', 'invalid_signature');
    }
    const signature = decodeBase64Url(value.signature, P256_SIGNATURE_BYTES);
    if (signature.byteLength !== P256_SIGNATURE_BYTES) {
        throw new ProtocolError('Handshake signature must be 64-byte P1363.', 'invalid_signature');
    }
    return { core: value.core, signature: value.signature };
}

function offerCoreFrom(value: SignedHandshakeOffer | HandshakeOfferCore): HandshakeOfferCore {
    if (isPlainRecord(value) && 'core' in value) {
        return validateHandshakeOfferCore((value as { core: unknown }).core);
    }
    return validateHandshakeOfferCore(value);
}

function assertMessageOptions(options: SignedMessageOptions): {
    issuedAt: number;
    expiresAt: number;
    nonce: Uint8Array;
} {
    const issuedAt = options.issuedAt ?? Date.now();
    const expiresAt = options.expiresAt;
    requireSafeInteger(issuedAt, 'issued_at');
    requireSafeInteger(expiresAt, 'expires_at');
    if (expiresAt <= issuedAt) {
        throw new ProtocolError('Handshake expiry must be after issue time.', 'invalid_handshake');
    }
    const nonce = options.nonce === undefined ? randomBytes(32) : copyBytes(options.nonce);
    if (nonce.byteLength !== 32) {
        throw new ProtocolError('Handshake nonce must be 32 bytes.', 'invalid_handshake');
    }
    return { issuedAt, expiresAt, nonce };
}

export async function createHandshakeOffer(
    options: HandshakeOfferOptions,
): Promise<HandshakeOfferResult> {
    const { issuedAt, expiresAt, nonce } = assertMessageOptions(options);
    const ephemeralKeyPair = options.ephemeralKeyPair ?? (await generateP256AgreementKeyPair());
    const ephemeralSpki = await exportSpki(ephemeralKeyPair.publicKey);
    const core: HandshakeOfferCore = {
        v: TRANSFER_PROTOCOL_VERSION,
        type: 'handshake_offer',
        transfer_id: options.transferId,
        account_epoch: options.accountEpoch,
        sender_device_id: options.senderDeviceId,
        recipient_device_id: options.recipientDeviceId,
        sender_ephemeral_spki: encodeBase64Url(ephemeralSpki),
        sender_nonce: encodeBase64Url(nonce),
        issued_at: issuedAt,
        expires_at: expiresAt,
    };
    const validCore = validateHandshakeOfferCore(core, issuedAt);
    const signature = encodeBase64Url(
        await signP256(options.signingKey, canonicalJsonBytes(validCore)),
    );
    const result = { core: validCore, signature } as HandshakeOfferResult;
    Object.defineProperty(result, 'ephemeralKeyPair', {
        value: ephemeralKeyPair,
        enumerable: false,
        writable: false,
    });
    return result;
}

export async function createHandshakeAnswer(
    options: HandshakeAnswerOptions,
): Promise<HandshakeAnswerResult> {
    const offer = offerCoreFrom(options.offer);
    const { issuedAt, expiresAt, nonce } = assertMessageOptions(options);
    if (
        offer.transfer_id !== options.transferId ||
        offer.sender_device_id !== options.senderDeviceId ||
        offer.recipient_device_id !== options.recipientDeviceId ||
        offer.account_epoch !== options.accountEpoch
    ) {
        throw new ProtocolError(
            'Handshake answer identities do not match the offer.',
            'identity_mismatch',
        );
    }
    if (expiresAt > offer.expires_at) {
        throw new ProtocolError('Handshake answer cannot outlive the offer.', 'invalid_handshake');
    }
    const ephemeralKeyPair = options.ephemeralKeyPair ?? (await generateP256AgreementKeyPair());
    const ephemeralSpki = await exportSpki(ephemeralKeyPair.publicKey);
    const offerHash = await sha256(canonicalJsonBytes(offer));
    const core: HandshakeAnswerCore = {
        v: TRANSFER_PROTOCOL_VERSION,
        type: 'handshake_answer',
        transfer_id: offer.transfer_id,
        account_epoch: offer.account_epoch,
        sender_device_id: offer.sender_device_id,
        recipient_device_id: offer.recipient_device_id,
        offer_hash: encodeBase64Url(offerHash),
        recipient_ephemeral_spki: encodeBase64Url(ephemeralSpki),
        recipient_nonce: encodeBase64Url(nonce),
        issued_at: issuedAt,
        expires_at: expiresAt,
    };
    const validCore = validateHandshakeAnswerCore(core, issuedAt);
    const signature = encodeBase64Url(
        await signP256(options.signingKey, canonicalJsonBytes(validCore)),
    );
    const result = { core: validCore, signature } as HandshakeAnswerResult;
    Object.defineProperty(result, 'ephemeralKeyPair', {
        value: ephemeralKeyPair,
        enumerable: false,
        writable: false,
    });
    return result;
}

async function resolveSigningKey(value: CryptoKey | ByteInput): Promise<CryptoKey> {
    return value instanceof CryptoKey ? value : importP256Spki(value, 'signing');
}

function assertExpectedIdentity(
    message: HandshakeOfferCore | HandshakeAnswerCore,
    expected: HandshakeExpectations,
): void {
    if (expected.transferId !== undefined && message.transfer_id !== expected.transferId) {
        throw new ProtocolError(
            'Handshake transfer identifier does not match.',
            'identity_mismatch',
        );
    }
    if (expected.accountEpoch !== undefined && message.account_epoch !== expected.accountEpoch) {
        throw new ProtocolError('Handshake account epoch does not match.', 'identity_mismatch');
    }
    if (
        expected.senderDeviceId !== undefined &&
        message.sender_device_id !== expected.senderDeviceId
    ) {
        throw new ProtocolError('Handshake sender does not match.', 'identity_mismatch');
    }
    if (
        expected.recipientDeviceId !== undefined &&
        message.recipient_device_id !== expected.recipientDeviceId
    ) {
        throw new ProtocolError('Handshake recipient does not match.', 'identity_mismatch');
    }
}

export async function assertValidHandshakeOffer(
    value: SignedHandshakeOffer,
    senderPublicKey: CryptoKey | ByteInput,
    expectations: HandshakeExpectations = {},
): Promise<HandshakeOfferCore> {
    const wrapper = signedWrapper(value);
    const now = expectations.now ?? Date.now();
    const core = validateHandshakeOfferCore(wrapper.core, now);
    assertExpectedIdentity(core, expectations);
    const publicKey = await resolveSigningKey(senderPublicKey);
    if (
        !(await verifyP256(
            publicKey,
            canonicalJsonBytes(core),
            decodeBase64Url(wrapper.signature, P256_SIGNATURE_BYTES),
        ))
    ) {
        throw new ProtocolError('Handshake offer signature is invalid.', 'invalid_signature');
    }
    await importP256Spki(decodeBase64Url(core.sender_ephemeral_spki, 1024), 'agreement');
    return core;
}

export async function verifyHandshakeOffer(
    value: SignedHandshakeOffer,
    senderPublicKey: CryptoKey | ByteInput,
    expectations: HandshakeExpectations = {},
): Promise<boolean> {
    try {
        await assertValidHandshakeOffer(value, senderPublicKey, expectations);
        return true;
    } catch {
        return false;
    }
}

export async function assertValidHandshakeAnswer(
    value: SignedHandshakeAnswer,
    recipientPublicKey: CryptoKey | ByteInput,
    expectations: HandshakeAnswerExpectations,
): Promise<HandshakeAnswerCore> {
    const wrapper = signedWrapper(value);
    const offer = offerCoreFrom(expectations.offer);
    const now = expectations.now ?? Date.now();
    const core = validateHandshakeAnswerCore(wrapper.core, now);
    assertExpectedIdentity(core, expectations);
    if (
        core.transfer_id !== offer.transfer_id ||
        core.account_epoch !== offer.account_epoch ||
        core.sender_device_id !== offer.sender_device_id ||
        core.recipient_device_id !== offer.recipient_device_id
    ) {
        throw new ProtocolError(
            'Handshake answer identities do not match the offer.',
            'identity_mismatch',
        );
    }
    if (core.expires_at > offer.expires_at) {
        throw new ProtocolError('Handshake answer cannot outlive the offer.', 'invalid_handshake');
    }
    const expectedOfferHash = await sha256(canonicalJsonBytes(offer));
    if (!equalBytes(expectedOfferHash, decodeBase64Url(core.offer_hash, SHA256_BYTES))) {
        throw new ProtocolError('Handshake answer is bound to another offer.', 'offer_mismatch');
    }
    const publicKey = await resolveSigningKey(recipientPublicKey);
    if (
        !(await verifyP256(
            publicKey,
            canonicalJsonBytes(core),
            decodeBase64Url(wrapper.signature, P256_SIGNATURE_BYTES),
        ))
    ) {
        throw new ProtocolError('Handshake answer signature is invalid.', 'invalid_signature');
    }
    await importP256Spki(decodeBase64Url(core.recipient_ephemeral_spki, 1024), 'agreement');
    return core;
}

export async function verifyHandshakeAnswer(
    value: SignedHandshakeAnswer,
    recipientPublicKey: CryptoKey | ByteInput,
    expectations: HandshakeAnswerExpectations,
): Promise<boolean> {
    try {
        await assertValidHandshakeAnswer(value, recipientPublicKey, expectations);
        return true;
    } catch {
        return false;
    }
}

export function serializeSignedHandshakeMessage(
    message: SignedHandshakeOffer | SignedHandshakeAnswer,
): Uint8Array {
    const wrapper = signedWrapper(message);
    const core =
        isPlainRecord(wrapper.core) && wrapper.core.type === 'handshake_offer'
            ? validateHandshakeOfferCore(wrapper.core, Number.MIN_SAFE_INTEGER)
            : validateHandshakeAnswerCore(wrapper.core, Number.MIN_SAFE_INTEGER);
    return canonicalJsonBytes({ core, signature: wrapper.signature });
}

export function transcriptBytes(
    offer: HandshakeOfferCore,
    answer: HandshakeAnswerCore,
): Uint8Array {
    const offerBytes = canonicalJsonBytes(
        validateHandshakeOfferCore(offer, Number.MIN_SAFE_INTEGER),
    );
    const answerBytes = canonicalJsonBytes(
        validateHandshakeAnswerCore(answer, Number.MIN_SAFE_INTEGER),
    );
    const domainBytes = new TextEncoder().encode(TRANSCRIPT_DOMAIN);
    const output = new Uint8Array(
        domainBytes.byteLength + 1 + offerBytes.byteLength + 1 + answerBytes.byteLength,
    );
    output.set(domainBytes);
    output.set(offerBytes, domainBytes.byteLength + 1);
    output[domainBytes.byteLength] = 0;
    output[domainBytes.byteLength + 1 + offerBytes.byteLength] = 0;
    output.set(answerBytes, domainBytes.byteLength + offerBytes.byteLength + 2);
    return output;
}

export async function transcriptHash(
    offer: HandshakeOfferCore,
    answer: HandshakeAnswerCore,
): Promise<Uint8Array> {
    return sha256(transcriptBytes(offer, answer));
}

export const handshakeTranscriptBytes = transcriptBytes;
export const handshakeTranscriptHash = transcriptHash;

export type DerivedHandshakeMaterial = {
    transcriptHash: Uint8Array;
    s2rKey: CryptoKey;
    r2sKey: CryptoKey;
    s2rNoncePrefix: Uint8Array;
    r2sNoncePrefix: Uint8Array;
    confirmation: Uint8Array;
    role?: 'sender' | 'recipient';
    sendKey?: CryptoKey;
    receiveKey?: CryptoKey;
    sendNoncePrefix?: Uint8Array;
    receiveNoncePrefix?: Uint8Array;
};

export type DeriveHandshakeMaterialOptions = {
    offer: HandshakeOfferCore;
    answer: HandshakeAnswerCore;
    localEphemeralPrivateKey: CryptoKey;
    remoteEphemeralSpki: ByteInput;
    role?: 'sender' | 'recipient';
};

async function hkdfExpand(
    ikm: Uint8Array,
    salt: Uint8Array,
    labelSuffix: string,
    length: number,
): Promise<Uint8Array> {
    const hkdfKey = await cryptoProvider().subtle.importKey(
        'raw',
        asBufferSource(ikm),
        'HKDF',
        false,
        ['deriveBits'],
    );
    const info = new TextEncoder().encode(`${KEY_DERIVATION_DOMAIN}${labelSuffix}`);
    const bits = await cryptoProvider().subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: asBufferSource(salt), info: asBufferSource(info) },
        hkdfKey,
        length * 8,
    );
    return copyBytes(bits);
}

export async function deriveHandshakeMaterial(
    options: DeriveHandshakeMaterialOptions,
): Promise<DerivedHandshakeMaterial> {
    const offer = validateHandshakeOfferCore(options.offer, Number.MIN_SAFE_INTEGER);
    const answer = validateHandshakeAnswerCore(options.answer, Number.MIN_SAFE_INTEGER);
    if (
        offer.transfer_id !== answer.transfer_id ||
        offer.account_epoch !== answer.account_epoch ||
        offer.sender_device_id !== answer.sender_device_id ||
        offer.recipient_device_id !== answer.recipient_device_id
    ) {
        throw new ProtocolError(
            'Handshake transcript identities do not match.',
            'identity_mismatch',
        );
    }
    const transcript = await transcriptHash(offer, answer);
    const remotePublicKey = await importP256Spki(options.remoteEphemeralSpki, 'agreement');
    let sharedSecret: Uint8Array | undefined;
    try {
        sharedSecret = copyBytes(
            await cryptoProvider().subtle.deriveBits(
                { name: 'ECDH', public: remotePublicKey },
                options.localEphemeralPrivateKey,
                256,
            ),
        );
        const [s2rKeyBytes, r2sKeyBytes, s2rNoncePrefix, r2sNoncePrefix, confirmation] =
            await Promise.all([
                hkdfExpand(sharedSecret, transcript, 's2r-key', 32),
                hkdfExpand(sharedSecret, transcript, 'r2s-key', 32),
                hkdfExpand(sharedSecret, transcript, 's2r-nonce-prefix', 4),
                hkdfExpand(sharedSecret, transcript, 'r2s-nonce-prefix', 4),
                hkdfExpand(sharedSecret, transcript, 'confirmation', 32),
            ]);
        const [s2rKey, r2sKey] = await Promise.all([
            cryptoProvider().subtle.importKey(
                'raw',
                asBufferSource(s2rKeyBytes),
                { name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt'],
            ),
            cryptoProvider().subtle.importKey(
                'raw',
                asBufferSource(r2sKeyBytes),
                { name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt'],
            ),
        ]);
        const material: DerivedHandshakeMaterial = {
            transcriptHash: transcript,
            s2rKey,
            r2sKey,
            s2rNoncePrefix,
            r2sNoncePrefix,
            confirmation,
            role: options.role,
        };
        if (options.role === 'sender') {
            material.sendKey = s2rKey;
            material.receiveKey = r2sKey;
            material.sendNoncePrefix = s2rNoncePrefix;
            material.receiveNoncePrefix = r2sNoncePrefix;
        } else if (options.role === 'recipient') {
            material.sendKey = r2sKey;
            material.receiveKey = s2rKey;
            material.sendNoncePrefix = r2sNoncePrefix;
            material.receiveNoncePrefix = s2rNoncePrefix;
        }
        return material;
    } finally {
        if (sharedSecret) {
            sharedSecret.fill(0);
        }
    }
}

export const deriveHandshakeKeys = deriveHandshakeMaterial;

export function disposeHandshakeMaterial(material: DerivedHandshakeMaterial): void {
    material.transcriptHash.fill(0);
    material.s2rNoncePrefix.fill(0);
    material.r2sNoncePrefix.fill(0);
    material.confirmation.fill(0);
    material.sendNoncePrefix?.fill(0);
    material.receiveNoncePrefix?.fill(0);
}

export const FRAME_HEADER_BYTES = 31;
export const FRAME_TAG_BYTES = 16;
export const MAX_FRAME_PLAINTEXT_BYTES = 64 * 1024;
export const MAX_FRAME_BYTES = FRAME_HEADER_BYTES + MAX_FRAME_PLAINTEXT_BYTES + FRAME_TAG_BYTES;
export const MAX_FRAME_COUNTER = (1n << 64n) - 1n;
export const CONFIRMATION_BYTES = 32;

export type FrameDirection = 's2r' | 'r2s';
export type FrameType =
    | 'confirm'
    | 'manifest'
    | 'chunk'
    | 'complete'
    | 'receipt'
    | 'cancel'
    | 'error';

export type FrameHeader = {
    v: typeof TRANSFER_PROTOCOL_VERSION;
    transfer_id: string;
    direction: FrameDirection;
    type: FrameType;
    counter: bigint | number;
    plaintext_length: number;
};

export type ParsedFrame = {
    header: Omit<FrameHeader, 'counter'> & { counter: bigint };
    ciphertext: Uint8Array;
};

export type EncryptFrameOptions = {
    key: CryptoKey;
    noncePrefix: ByteInput;
    header: FrameHeader;
    plaintext: ByteInput;
};

export type DecryptFrameOptions = {
    key: CryptoKey;
    noncePrefix: ByteInput;
    frame: ByteInput;
    expectedTransferId?: string;
    expectedDirection?: FrameDirection;
    expectedCounter?: bigint | number;
};

const FRAME_TYPE_TO_CODE: Record<FrameType, number> = {
    confirm: 0,
    manifest: 1,
    chunk: 2,
    complete: 3,
    receipt: 4,
    cancel: 5,
    error: 6,
};

const FRAME_CODE_TO_TYPE: Record<number, FrameType> = {
    0: 'confirm',
    1: 'manifest',
    2: 'chunk',
    3: 'complete',
    4: 'receipt',
    5: 'cancel',
    6: 'error',
};

function requireFrameDirection(value: unknown): FrameDirection {
    if (value !== 's2r' && value !== 'r2s') {
        throw new ProtocolError('Frame direction is invalid.', 'invalid_frame');
    }
    return value;
}

function requireFrameType(value: unknown): FrameType {
    if (typeof value !== 'string' || !(value in FRAME_TYPE_TO_CODE)) {
        throw new ProtocolError('Frame type is invalid.', 'invalid_frame');
    }
    return value as FrameType;
}

function requireFrameCounter(value: bigint | number): bigint {
    let counter: bigint;
    if (typeof value === 'bigint') {
        counter = value;
    } else if (typeof value === 'number' && Number.isSafeInteger(value)) {
        counter = BigInt(value);
    } else {
        throw new ProtocolError('Frame counter is invalid.', 'invalid_counter');
    }
    if (counter < 0n || counter > MAX_FRAME_COUNTER) {
        throw new ProtocolError('Frame counter is outside the uint64 range.', 'invalid_counter');
    }
    return counter;
}

function requireFrameLength(value: unknown): number {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > MAX_FRAME_PLAINTEXT_BYTES
    ) {
        throw new ProtocolError('Frame plaintext length is invalid.', 'invalid_length');
    }
    return value;
}

function uuidToBytes(value: string): Uint8Array {
    if (!UUID_PATTERN.test(value)) {
        throw new ProtocolError('Frame transfer identifier is invalid.', 'invalid_frame');
    }
    const hex = value.replace(/-/gu, '');
    const bytes = new Uint8Array(16);
    for (let index = 0; index < bytes.length; index += 1) {
        bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
}

function bytesToUuid(bytes: Uint8Array): string {
    if (bytes.byteLength !== 16) {
        throw new ProtocolError('Frame transfer identifier is invalid.', 'invalid_frame');
    }
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function frameDirectionCode(direction: FrameDirection): number {
    return direction === 's2r' ? 0 : 1;
}

function codeToFrameDirection(code: number): FrameDirection {
    if (code === 0) {
        return 's2r';
    }
    if (code === 1) {
        return 'r2s';
    }
    throw new ProtocolError('Frame direction is invalid.', 'invalid_frame');
}

function oppositeDirection(direction: FrameDirection): FrameDirection {
    return direction === 's2r' ? 'r2s' : 's2r';
}

function validateFrameTypeDirection(direction: FrameDirection, type: FrameType): void {
    if ((type === 'manifest' || type === 'chunk' || type === 'complete') && direction !== 's2r') {
        throw new ProtocolError('Frame type is not valid for this direction.', 'invalid_frame');
    }
    if (type === 'receipt' && direction !== 'r2s') {
        throw new ProtocolError('Frame type is not valid for this direction.', 'invalid_frame');
    }
}

/** Encode the fixed 31-byte authenticated frame header. */
export function encodeFrameHeader(header: FrameHeader): Uint8Array {
    if (header.v !== TRANSFER_PROTOCOL_VERSION) {
        throw new ProtocolError('Frame version is unsupported.', 'unsupported_version');
    }
    const transferId = requireUuid(header.transfer_id, 'transfer_id');
    const direction = requireFrameDirection(header.direction);
    const type = requireFrameType(header.type);
    const counter = requireFrameCounter(header.counter);
    const plaintextLength = requireFrameLength(header.plaintext_length);
    validateFrameTypeDirection(direction, type);
    const output = new Uint8Array(FRAME_HEADER_BYTES);
    const view = new DataView(output.buffer);
    view.setUint8(0, TRANSFER_PROTOCOL_VERSION);
    output.set(uuidToBytes(transferId), 1);
    view.setUint8(17, frameDirectionCode(direction));
    view.setUint8(18, FRAME_TYPE_TO_CODE[type]);
    view.setBigUint64(19, counter, false);
    view.setUint32(27, plaintextLength, false);
    return output;
}

/** Parse and validate a complete fixed-size frame header. */
export function parseFrameHeader(value: ByteInput): ParsedFrame['header'] {
    const bytes = copyBytes(value);
    if (bytes.byteLength !== FRAME_HEADER_BYTES) {
        throw new ProtocolError('Frame header has an invalid length.', 'invalid_length');
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (view.getUint8(0) !== TRANSFER_PROTOCOL_VERSION) {
        throw new ProtocolError('Frame version is unsupported.', 'unsupported_version');
    }
    const direction = codeToFrameDirection(view.getUint8(17));
    const type = FRAME_CODE_TO_TYPE[view.getUint8(18)];
    if (type === undefined) {
        throw new ProtocolError('Frame type is invalid.', 'invalid_frame');
    }
    const counter = view.getBigUint64(19, false);
    const plaintextLength = view.getUint32(27, false);
    requireFrameLength(plaintextLength);
    validateFrameTypeDirection(direction, type);
    return {
        v: TRANSFER_PROTOCOL_VERSION,
        transfer_id: bytesToUuid(bytes.slice(1, 17)),
        direction,
        type,
        counter,
        plaintext_length: plaintextLength,
    };
}

export function frameNonce(noncePrefix: ByteInput, counter: bigint | number): Uint8Array {
    const prefix = copyBytes(noncePrefix);
    if (prefix.byteLength !== 4) {
        throw new ProtocolError('Frame nonce prefix must be 4 bytes.', 'invalid_nonce');
    }
    const normalizedCounter = requireFrameCounter(counter);
    const nonce = new Uint8Array(12);
    nonce.set(prefix);
    new DataView(nonce.buffer).setBigUint64(4, normalizedCounter, false);
    return nonce;
}

export const buildFrameNonce = frameNonce;

export async function encryptFrame(options: EncryptFrameOptions): Promise<Uint8Array> {
    const plaintext = copyBytes(options.plaintext);
    if (options.header.plaintext_length !== plaintext.byteLength) {
        throw new ProtocolError(
            'Frame plaintext length does not match the header.',
            'invalid_length',
        );
    }
    const header = options.header;
    const headerBytes = encodeFrameHeader(header);
    try {
        const ciphertext = copyBytes(
            await cryptoProvider().subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: asBufferSource(frameNonce(options.noncePrefix, header.counter)),
                    additionalData: asBufferSource(headerBytes),
                    tagLength: 128,
                },
                options.key,
                asBufferSource(plaintext),
            ),
        );
        if (ciphertext.byteLength !== plaintext.byteLength + FRAME_TAG_BYTES) {
            throw new ProtocolError('AES-GCM returned an invalid frame.', 'crypto_failure');
        }
        const output = new Uint8Array(headerBytes.byteLength + ciphertext.byteLength);
        output.set(headerBytes);
        output.set(ciphertext, headerBytes.byteLength);
        return output;
    } catch (error) {
        if (error instanceof ProtocolError) {
            throw error;
        }
        throw new ProtocolError('Unable to encrypt the frame.', 'crypto_failure');
    }
}

export function splitFrame(value: ByteInput): {
    header: ParsedFrame['header'];
    ciphertext: Uint8Array;
} {
    const bytes = copyBytes(value);
    if (
        bytes.byteLength < FRAME_HEADER_BYTES + FRAME_TAG_BYTES ||
        bytes.byteLength > MAX_FRAME_BYTES
    ) {
        throw new ProtocolError('Frame has an invalid length.', 'invalid_length');
    }
    const header = parseFrameHeader(bytes.slice(0, FRAME_HEADER_BYTES));
    const expectedLength = FRAME_HEADER_BYTES + header.plaintext_length + FRAME_TAG_BYTES;
    if (bytes.byteLength !== expectedLength) {
        throw new ProtocolError('Frame length does not match its header.', 'invalid_length');
    }
    return { header, ciphertext: bytes.slice(FRAME_HEADER_BYTES) };
}

export async function decryptFrame(
    options: DecryptFrameOptions,
): Promise<ParsedFrame & { plaintext: Uint8Array }> {
    const { header, ciphertext } = splitFrame(options.frame);
    if (
        options.expectedTransferId !== undefined &&
        header.transfer_id !== options.expectedTransferId
    ) {
        throw new ProtocolError('Frame transfer identifier does not match.', 'identity_mismatch');
    }
    if (options.expectedDirection !== undefined && header.direction !== options.expectedDirection) {
        throw new ProtocolError('Frame direction does not match.', 'direction_mismatch');
    }
    const actualCounter = requireFrameCounter(header.counter);
    if (
        options.expectedCounter !== undefined &&
        actualCounter !== requireFrameCounter(options.expectedCounter)
    ) {
        throw new ProtocolError('Frame counter is out of order.', 'counter_mismatch');
    }
    try {
        const plaintext = copyBytes(
            await cryptoProvider().subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: asBufferSource(frameNonce(options.noncePrefix, header.counter)),
                    additionalData: asBufferSource(encodeFrameHeader(header)),
                    tagLength: 128,
                },
                options.key,
                asBufferSource(ciphertext),
            ),
        );
        if (plaintext.byteLength !== header.plaintext_length) {
            throw new ProtocolError('Frame plaintext length does not match.', 'invalid_length');
        }
        return { header, ciphertext, plaintext };
    } catch (error) {
        if (error instanceof ProtocolError) {
            throw error;
        }
        throw new ProtocolError('Frame authentication failed.', 'authentication_failed');
    }
}

export class FrameCounter {
    private nextValue = 0n;

    constructor(initialValue: bigint | number = 0n) {
        this.nextValue = requireFrameCounter(initialValue);
    }

    get next(): bigint {
        return this.nextValue;
    }

    reserve(): bigint {
        if (this.nextValue > MAX_FRAME_COUNTER) {
            throw new ProtocolError('Frame counter wrapped.', 'counter_wraparound');
        }
        const value = this.nextValue;
        this.nextValue += 1n;
        return value;
    }

    accept(value: bigint | number): void {
        const counter = requireFrameCounter(value);
        if (counter !== this.nextValue) {
            throw new ProtocolError(
                'Frame counter is duplicated or out of order.',
                'counter_mismatch',
            );
        }
        if (this.nextValue === MAX_FRAME_COUNTER) {
            this.nextValue = MAX_FRAME_COUNTER + 1n;
            return;
        }
        this.nextValue += 1n;
    }
}

export type FrameStreamOptions = {
    transferId: string;
    direction: FrameDirection;
    confirmation?: ByteInput;
};

function sameBytes(left: ByteInput, right: ByteInput): boolean {
    return equalBytes(left, right);
}

function sequenceTypeAllowed(
    previous: FrameType | null,
    next: FrameType,
    direction: FrameDirection,
): boolean {
    if (next === 'confirm') {
        return previous === null;
    }
    if (previous === null || previous === 'confirm') {
        return next === 'manifest' || next === 'receipt' || next === 'cancel' || next === 'error';
    }
    if (next === 'chunk') {
        return direction === 's2r' && (previous === 'manifest' || previous === 'chunk');
    }
    if (next === 'complete') {
        return direction === 's2r' && (previous === 'manifest' || previous === 'chunk');
    }
    if (next === 'receipt') {
        return direction === 'r2s' && previous === 'complete';
    }
    return next === 'cancel' || next === 'error';
}

/** Stateful stream guard for ordered counters and handshake confirmation. */
export class FrameStream {
    readonly transferId: string;
    readonly direction: FrameDirection;
    readonly receiveDirection: FrameDirection;
    private readonly sendCounter = new FrameCounter();
    private readonly receiveCounter = new FrameCounter();
    private readonly confirmation?: Uint8Array;
    private sentConfirmation = false;
    private receivedConfirmation = false;
    private sentType: FrameType | null = null;
    private receivedType: FrameType | null = null;

    constructor(options: FrameStreamOptions) {
        this.transferId = requireUuid(options.transferId, 'transfer_id');
        this.direction = requireFrameDirection(options.direction);
        this.receiveDirection = oppositeDirection(this.direction);
        if (options.confirmation !== undefined) {
            const confirmation = copyBytes(options.confirmation);
            if (confirmation.byteLength !== CONFIRMATION_BYTES) {
                throw new ProtocolError('Confirmation must be 32 bytes.', 'invalid_confirmation');
            }
            this.confirmation = confirmation;
        }
    }

    get isConfirmed(): boolean {
        return this.sentConfirmation && this.receivedConfirmation;
    }

    get nextSendCounter(): bigint {
        return this.sendCounter.next;
    }

    get nextReceiveCounter(): bigint {
        return this.receiveCounter.next;
    }

    async createFrame(
        key: CryptoKey,
        noncePrefix: ByteInput,
        type: FrameType,
        plaintext: ByteInput,
    ): Promise<Uint8Array> {
        const normalizedType = requireFrameType(type);
        validateFrameTypeDirection(this.direction, normalizedType);
        const body = copyBytes(plaintext);
        if (!sequenceTypeAllowed(this.sentType, normalizedType, this.direction)) {
            throw new ProtocolError(
                'Frame type is invalid for the current stream state.',
                'invalid_state',
            );
        }
        if (!this.sentConfirmation && normalizedType !== 'confirm') {
            throw new ProtocolError('Confirmation must be sent first.', 'confirmation_required');
        }
        if (normalizedType === 'confirm') {
            if (
                this.sentConfirmation ||
                this.sendCounter.next !== 0n ||
                body.byteLength !== CONFIRMATION_BYTES
            ) {
                throw new ProtocolError('Confirmation frame is invalid.', 'invalid_confirmation');
            }
            if (this.confirmation && !sameBytes(this.confirmation, body)) {
                throw new ProtocolError(
                    'Confirmation value does not match the transcript.',
                    'invalid_confirmation',
                );
            }
        } else if (!this.receivedConfirmation) {
            throw new ProtocolError(
                'Peer confirmation is required before data.',
                'confirmation_required',
            );
        }
        const frame = await encryptFrame({
            key,
            noncePrefix,
            header: {
                v: TRANSFER_PROTOCOL_VERSION,
                transfer_id: this.transferId,
                direction: this.direction,
                type: normalizedType,
                counter: this.sendCounter.reserve(),
                plaintext_length: body.byteLength,
            },
            plaintext: body,
        });
        this.sentCounterApplied(normalizedType);
        return frame;
    }

    private sentCounterApplied(type: FrameType): void {
        if (type === 'confirm') {
            this.sentConfirmation = true;
        }
        this.sentType = type;
    }

    async receiveFrame(
        key: CryptoKey,
        noncePrefix: ByteInput,
        frame: ByteInput,
    ): Promise<ParsedFrame & { plaintext: Uint8Array }> {
        const parsed = splitFrame(frame);
        if (
            parsed.header.transfer_id !== this.transferId ||
            parsed.header.direction !== this.receiveDirection
        ) {
            throw new ProtocolError(
                'Frame identity or direction does not match.',
                'identity_mismatch',
            );
        }
        const type = parsed.header.type;
        if (!sequenceTypeAllowed(this.receivedType, type, this.receiveDirection)) {
            throw new ProtocolError(
                'Frame type is invalid for the current stream state.',
                'invalid_state',
            );
        }
        if (parsed.header.counter !== this.receiveCounter.next) {
            throw new ProtocolError(
                'Frame counter is duplicated or out of order.',
                'counter_mismatch',
            );
        }
        try {
            const result = await decryptFrame({
                key,
                noncePrefix,
                frame,
                expectedTransferId: this.transferId,
                expectedDirection: this.receiveDirection,
                expectedCounter: this.receiveCounter.next,
            });
            this.receiveCounter.accept(parsed.header.counter);
            if (!this.receivedConfirmation && type !== 'confirm') {
                throw new ProtocolError(
                    'Confirmation must be received first.',
                    'confirmation_required',
                );
            }
            if (type === 'confirm') {
                if (
                    this.receivedConfirmation ||
                    parsed.header.counter !== 0n ||
                    result.plaintext.byteLength !== CONFIRMATION_BYTES
                ) {
                    throw new ProtocolError(
                        'Confirmation frame is invalid.',
                        'invalid_confirmation',
                    );
                }
                if (this.confirmation && !sameBytes(this.confirmation, result.plaintext)) {
                    throw new ProtocolError(
                        'Confirmation value does not match the transcript.',
                        'invalid_confirmation',
                    );
                }
                this.receivedConfirmation = true;
            }
            this.receivedType = type;
            return result;
        } catch (error) {
            throw error instanceof ProtocolError
                ? error
                : new ProtocolError('Frame processing failed.', 'invalid_frame');
        }
    }
}

export const EncryptedFrameStream = FrameStream;

export function confirmationPayload(material: DerivedHandshakeMaterial): Uint8Array {
    return copyBytes(material.confirmation);
}

export async function createConfirmationFrame(
    stream: FrameStream,
    key: CryptoKey,
    noncePrefix: ByteInput,
    confirmation: ByteInput,
): Promise<Uint8Array> {
    return stream.createFrame(key, noncePrefix, 'confirm', confirmation);
}
