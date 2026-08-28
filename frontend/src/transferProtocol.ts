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
