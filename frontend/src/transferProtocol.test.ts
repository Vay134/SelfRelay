import { describe, expect, it } from 'vitest';

import {
    canonicalJson,
    canonicalJsonBytes,
    decodeBase64Url,
    derToP1363,
    encodeBase64Url,
    exportSpki,
    fingerprintSpki,
    generateP256SigningKeyPair,
    importP256Spki,
    p1363ToDer,
    parseCanonicalJson,
    parseStrictJson,
    signP256,
    verifyP256,
} from './transferProtocol';

describe('transfer protocol primitives', () => {
    it('serializes RFC 8785 object keys by UTF-16 code units', () => {
        expect(
            canonicalJson({ 10: 'ten', 2: 'two', '\u{10000}': 'astral', '\uE000': 'private' }),
        ).toBe('{"10":"ten","2":"two","𐀀":"astral","":"private"}');
        expect(canonicalJson({ number: -0, small: 1e-7, large: 1e21 })).toBe(
            '{"large":1e+21,"number":0,"small":1e-7}',
        );
    });

    it('rejects unsupported canonical values and duplicate JSON keys', () => {
        expect(() => canonicalJson({ value: Number.NaN })).toThrow(/non-finite/u);
        expect(() => canonicalJson({ value: undefined })).toThrow(/support/u);
        expect(() => parseStrictJson('{"a":1,"a":2}')).toThrow(/duplicate/u);
        expect(() => parseCanonicalJson('{ "a": 1 }')).toThrow(/canonical/u);
        expect(parseCanonicalJson(canonicalJsonBytes({ a: [true, null, 'ok'] }))).toEqual({
            a: [true, null, 'ok'],
        });
    });

    it('round-trips strict unpadded base64url and rejects malformed input', () => {
        const value = Uint8Array.from([0, 1, 2, 251, 252, 253, 254, 255]);
        const encoded = encodeBase64Url(value);
        expect(encoded).toBe('AAEC-_z9_v8');
        expect(decodeBase64Url(encoded)).toEqual(value);
        expect(() => decodeBase64Url('AA==')).toThrow(/base64/u);
        expect(() => decodeBase64Url('A')).toThrow(/base64/u);
        expect(decodeBase64Url('')).toEqual(new Uint8Array());
    });

    it('converts strict P1363 signatures to and from DER', () => {
        const signature = Uint8Array.from(
            Array.from({ length: 64 }, (_, index) => (index === 0 || index === 32 ? 0x80 : index)),
        );
        const der = p1363ToDer(signature);
        expect(derToP1363(der)).toEqual(signature);
        expect(() => derToP1363(Uint8Array.of(0x30, 0x00))).toThrow(/signature/u);
        expect(() => p1363ToDer(new Uint8Array(63))).toThrow(/64/u);
    });

    it('imports, exports, fingerprints, signs, and verifies P-256 keys', async () => {
        const keyPair = await generateP256SigningKeyPair();
        const spki = await exportSpki(keyPair.publicKey);
        const imported = await importP256Spki(spki);
        const fingerprint = await fingerprintSpki(spki);
        expect(fingerprint).toMatch(/^[A-Za-z0-9_-]{43}$/u);

        const message = new TextEncoder().encode('transfer protocol test');
        const signature = await signP256(keyPair.privateKey, message);
        expect(signature).toHaveLength(64);
        await expect(verifyP256(imported, message, signature)).resolves.toBe(true);
        await expect(
            verifyP256(imported, new TextEncoder().encode('tampered'), signature),
        ).resolves.toBe(false);
    });
});
