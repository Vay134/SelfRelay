import {
    canonicalJson as protocolCanonicalJson,
    canonicalJsonBytes as protocolCanonicalJsonBytes,
    decodeBase64Url as protocolDecodeBase64Url,
    encodeBase64Url as protocolEncodeBase64Url,
    normalizeP1363Signature,
} from './transferProtocol';

/**
 * Browser-owned device identity.
 *
 * The private CryptoKey is deliberately stored as a structured-cloned key in
 * IndexedDB.  It is generated with extractable=false, so this module never
 * has a private-key byte representation to put in localStorage, a cookie, or
 * an API request.
 */

export const DEVICE_DATABASE_NAME = 'e2e-secure-file-transfer-device';
export const DEVICE_DATABASE_VERSION = 1;
export const DEVICE_STORE_NAME = 'identity';
export const DEVICE_STORE_KEY = 'current';
export const DEVICE_PROTOCOL_VERSION = 1;
export const DEVICE_CHALLENGE_VERSION = 1;
export const DEVICE_AUTH_DOMAIN = 'e2e-secure-file-transfer/device-auth/v1\u0000';

export type DeviceIdentity = {
    deviceId: string;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    publicKeySpki: Uint8Array;
    fingerprint: string;
};

type StoredDeviceIdentity = {
    deviceId: string;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    publicKeySpki: ArrayBuffer;
};

export class DeviceKeyMissingError extends Error {
    constructor(message = 'This browser does not have a device key.') {
        super(message);
        this.name = 'DeviceKeyMissingError';
    }
}

export class DeviceStorageUnavailableError extends Error {
    constructor(message = 'Secure browser key storage is unavailable.') {
        super(message);
        this.name = 'DeviceStorageUnavailableError';
    }
}

function browserCrypto(): Crypto {
    const available = globalThis.crypto;
    if (!available?.subtle) {
        throw new DeviceStorageUnavailableError('Web Crypto is unavailable in this browser.');
    }
    return available;
}

function browserIndexedDb(): IDBFactory {
    const available = globalThis.indexedDB;
    if (!available) {
        throw new DeviceStorageUnavailableError('IndexedDB is unavailable in this browser.');
    }
    return available;
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new DeviceStorageUnavailableError());
    });
}

function openDatabase(): Promise<IDBDatabase> {
    const request = browserIndexedDb().open(DEVICE_DATABASE_NAME, DEVICE_DATABASE_VERSION);
    request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains(DEVICE_STORE_NAME)) {
            database.createObjectStore(DEVICE_STORE_NAME);
        }
    };
    return requestResult(request);
}

async function readStoredIdentity(): Promise<StoredDeviceIdentity | undefined> {
    const database = await openDatabase();
    try {
        const transaction = database.transaction(DEVICE_STORE_NAME, 'readonly');
        return await requestResult(
            transaction.objectStore(DEVICE_STORE_NAME).get(DEVICE_STORE_KEY),
        );
    } finally {
        database.close();
    }
}

async function writeStoredIdentity(identity: StoredDeviceIdentity): Promise<void> {
    const database = await openDatabase();
    try {
        await new Promise<void>((resolve, reject) => {
            const transaction = database.transaction(DEVICE_STORE_NAME, 'readwrite');
            transaction.oncomplete = () => resolve();
            transaction.onerror = () =>
                reject(transaction.error ?? new DeviceStorageUnavailableError());
            transaction.onabort = () =>
                reject(transaction.error ?? new DeviceStorageUnavailableError());
            transaction.objectStore(DEVICE_STORE_NAME).put(identity, DEVICE_STORE_KEY);
        });
    } finally {
        database.close();
    }
}

function copyBytes(value: ArrayBuffer | Uint8Array): Uint8Array {
    return value instanceof Uint8Array ? new Uint8Array(value) : new Uint8Array(value.slice(0));
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
    return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

function randomUuid(): string {
    const available = browserCrypto();
    if (typeof available.randomUUID === 'function') {
        return available.randomUUID();
    }
    const bytes = new Uint8Array(16);
    available.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Return a recognizable editable label without collecting a hardware identifier. */
export function getDefaultDeviceLabel(): string {
    if (typeof navigator === 'undefined') {
        return 'This browser';
    }
    const userAgent = navigator.userAgent;
    const hints = navigator as Navigator & {
        userAgentData?: { mobile?: boolean; model?: string; platform?: string };
    };
    const platform = hints.userAgentData?.platform || navigator.platform || userAgent;
    const model = hints.userAgentData?.model?.trim();
    const operatingSystem = /Android/iu.test(platform)
        ? 'Android'
        : /iPhone/iu.test(userAgent)
          ? 'iPhone'
          : /iPad/iu.test(userAgent)
            ? 'iPad'
            : /Windows/iu.test(platform)
              ? 'Windows'
              : /Mac/iu.test(platform)
                ? 'macOS'
                : /Linux/iu.test(platform)
                  ? 'Linux'
                  : 'device';
    const browser = /Edg\//u.test(userAgent)
        ? 'Edge'
        : /Firefox\//u.test(userAgent)
          ? 'Firefox'
          : /Chrome\//u.test(userAgent)
            ? 'Chrome'
            : /Safari\//u.test(userAgent)
              ? 'Safari'
              : 'Browser';
    return model ? `${model} · ${browser}` : `${browser} on ${operatingSystem}`;
}

export function encodeBase64Url(value: unknown): string {
    if (value instanceof Uint8Array || value instanceof ArrayBuffer) {
        return protocolEncodeBase64Url(value);
    }
    if (ArrayBuffer.isView(value)) {
        return protocolEncodeBase64Url(value);
    }
    throw new TypeError('A byte value is required.');
}

export function decodeBase64Url(value: string): Uint8Array {
    try {
        return protocolDecodeBase64Url(value);
    } catch (error) {
        throw new TypeError('Invalid base64url value.', { cause: error });
    }
}

export function canonicalJson(value: unknown): string {
    return protocolCanonicalJson(value);
}

export function canonicalJsonBytes(value: unknown): Uint8Array {
    return protocolCanonicalJsonBytes(value);
}

export function signedChallengeBytes(payload: unknown): Uint8Array {
    return signedDomainPayloadBytes(DEVICE_AUTH_DOMAIN, payload);
}

export function signedDomainPayloadBytes(domain: string, payload: unknown): Uint8Array {
    if (!domain || domain.includes('\u0000') === false) {
        throw new TypeError('A domain separator is required.');
    }
    const domainBytes = new TextEncoder().encode(domain);
    const body = canonicalJsonBytes(payload);
    const result = new Uint8Array(domainBytes.byteLength + body.byteLength);
    result.set(domainBytes);
    result.set(body, domainBytes.byteLength);
    return result;
}

export async function exportSpki(publicKey: CryptoKey): Promise<Uint8Array> {
    return copyBytes(await browserCrypto().subtle.exportKey('spki', publicKey));
}

export async function fingerprintSpki(publicKeySpki: BufferSource): Promise<string> {
    const digest = await browserCrypto().subtle.digest('SHA-256', publicKeySpki as BufferSource);
    return encodeBase64Url(digest);
}

export async function createDeviceIdentity(deviceId = randomUuid()): Promise<DeviceIdentity> {
    const keyPair = (await browserCrypto().subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify'],
    )) as CryptoKeyPair;
    const publicKeySpki = await exportSpki(keyPair.publicKey);
    const fingerprint = await fingerprintSpki(publicKeySpki as BufferSource);
    const identity: DeviceIdentity = {
        deviceId,
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        publicKeySpki,
        fingerprint,
    };
    await writeStoredIdentity({
        deviceId,
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        publicKeySpki: toArrayBuffer(publicKeySpki),
    });
    return identity;
}

export async function loadDeviceIdentity(): Promise<DeviceIdentity | null> {
    const stored = await readStoredIdentity();
    if (!stored) {
        return null;
    }
    if (stored.privateKey.type !== 'private' || stored.publicKey.type !== 'public') {
        throw new DeviceKeyMissingError('The saved device key is not usable.');
    }
    const publicKeySpki = copyBytes(stored.publicKeySpki);
    return {
        deviceId: stored.deviceId,
        privateKey: stored.privateKey,
        publicKey: stored.publicKey,
        publicKeySpki,
        fingerprint: await fingerprintSpki(publicKeySpki as BufferSource),
    };
}

export async function getOrCreateDeviceIdentity(): Promise<DeviceIdentity> {
    const existing = await loadDeviceIdentity();
    return existing ?? createDeviceIdentity();
}

export async function clearDeviceIdentity(): Promise<void> {
    const database = await openDatabase();
    try {
        await new Promise<void>((resolve, reject) => {
            const transaction = database.transaction(DEVICE_STORE_NAME, 'readwrite');
            transaction.oncomplete = () => resolve();
            transaction.onerror = () =>
                reject(transaction.error ?? new DeviceStorageUnavailableError());
            transaction.onabort = () =>
                reject(transaction.error ?? new DeviceStorageUnavailableError());
            transaction.objectStore(DEVICE_STORE_NAME).delete(DEVICE_STORE_KEY);
        });
    } finally {
        database.close();
    }
}

export async function signPayload(identity: DeviceIdentity, payload: unknown): Promise<Uint8Array> {
    return signDomainPayloadBytes(identity, DEVICE_AUTH_DOMAIN, payload);
}

async function signDomainPayloadBytes(
    identity: DeviceIdentity,
    domain: string,
    payload: unknown,
): Promise<Uint8Array> {
    const signature = await browserCrypto().subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        identity.privateKey,
        signedDomainPayloadBytes(domain, payload) as BufferSource,
    );
    const bytes = normalizeP1363Signature(signature);
    if (bytes.byteLength !== 64) {
        throw new DeviceStorageUnavailableError(
            'This browser returned an unsupported ECDSA signature.',
        );
    }
    return bytes;
}

export async function signChallenge(identity: DeviceIdentity, payload: unknown): Promise<string> {
    return encodeBase64Url(await signPayload(identity, payload));
}

export async function verifyPayloadSignature(
    publicKey: CryptoKey,
    payload: unknown,
    signature: BufferSource,
): Promise<boolean> {
    return browserCrypto().subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        signature as BufferSource,
        signedChallengeBytes(payload) as BufferSource,
    );
}

export async function deviceKeyStatus(): Promise<'available' | 'missing'> {
    return (await loadDeviceIdentity()) === null ? 'missing' : 'available';
}
