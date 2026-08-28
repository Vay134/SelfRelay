import { describe, expect, it } from 'vitest';

import {
    canonicalJson,
    canonicalJsonBytes,
    decodeBase64Url,
    derToP1363,
    encodeBase64Url,
    exportSpki,
    fingerprintSpki,
    createHandshakeAnswer,
    createHandshakeOffer,
    deriveHandshakeMaterial,
    decryptFrame,
    encodeFrameHeader,
    encryptFrame,
    FrameCounter,
    FrameStream,
    frameNonce,
    parseFrameHeader,
    splitFrame,
    generateP256SigningKeyPair,
    importP256Spki,
    p1363ToDer,
    parseCanonicalJson,
    parseStrictJson,
    signP256,
    transcriptBytes,
    transcriptHash,
    verifyHandshakeAnswer,
    verifyHandshakeOffer,
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

    it('rejects lone UTF-16 surrogates in RFC 8785 strings and keys', () => {
        const highSurrogate = '\uD800';
        const lowSurrogate = '\uDC00';
        const validPair = '\uD83D\uDE00';

        for (const value of [highSurrogate, lowSurrogate]) {
            expect(() => canonicalJson(value)).toThrow(/well-formed Unicode/u);
            expect(() => canonicalJson({ value })).toThrow(/well-formed Unicode/u);
        }
        expect(() => canonicalJson({ [highSurrogate]: 'value' })).toThrow(/well-formed Unicode/u);
        expect(() => parseCanonicalJson('{"value":"\\ud800"}')).toThrow(/well-formed Unicode/u);
        expect(canonicalJson({ value: validPair })).toBe('{"value":"😀"}');
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

    it('binds signed offer and answer messages to identities and the exact offer', async () => {
        const senderSigning = await generateP256SigningKeyPair();
        const recipientSigning = await generateP256SigningKeyPair();
        const now = Date.now();
        const common = {
            transferId: '11111111-1111-4111-8111-111111111111',
            accountEpoch: 4,
            senderDeviceId: '22222222-2222-4222-8222-222222222222',
            recipientDeviceId: '33333333-3333-4333-8333-333333333333',
            expiresAt: now + 30_000,
        };
        const offer = await createHandshakeOffer({
            ...common,
            issuedAt: now,
            signingKey: senderSigning.privateKey,
            nonce: new Uint8Array(32).fill(1),
        });
        const answer = await createHandshakeAnswer({
            ...common,
            issuedAt: now + 1,
            signingKey: recipientSigning.privateKey,
            nonce: new Uint8Array(32).fill(2),
            offer,
        });

        await expect(
            verifyHandshakeOffer(offer, senderSigning.publicKey, {
                transferId: common.transferId,
                accountEpoch: common.accountEpoch,
                senderDeviceId: common.senderDeviceId,
                recipientDeviceId: common.recipientDeviceId,
                now,
            }),
        ).resolves.toBe(true);
        await expect(
            verifyHandshakeAnswer(answer, recipientSigning.publicKey, {
                offer,
                transferId: common.transferId,
                accountEpoch: common.accountEpoch,
                senderDeviceId: common.senderDeviceId,
                recipientDeviceId: common.recipientDeviceId,
                now,
            }),
        ).resolves.toBe(true);
        const altered = {
            ...offer,
            core: { ...offer.core, recipient_device_id: common.senderDeviceId },
        };
        await expect(verifyHandshakeOffer(altered, senderSigning.publicKey, { now })).resolves.toBe(
            false,
        );
        const alteredAnswer = {
            ...answer,
            core: { ...answer.core, offer_hash: encodeBase64Url(new Uint8Array(32)) },
        };
        await expect(
            verifyHandshakeAnswer(alteredAnswer, recipientSigning.publicKey, { offer, now }),
        ).resolves.toBe(false);
    });

    it('rejects caller-supplied ephemeral material reused by another transfer', async () => {
        const senderSigning = await generateP256SigningKeyPair();
        const recipientSigning = await generateP256SigningKeyPair();
        const suppliedOfferEphemeral = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            ['deriveBits'],
        );
        const suppliedAnswerEphemeral = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            ['deriveBits'],
        );
        const now = Date.now();
        const senderDeviceId = '22222222-2222-4222-8222-222222222222';
        const recipientDeviceId = '33333333-3333-4333-8333-333333333333';
        const expiresAt = now + 30_000;

        await expect(
            createHandshakeOffer({
                transferId: '11111111-1111-4111-8111-111111111111',
                accountEpoch: 4,
                senderDeviceId,
                recipientDeviceId,
                issuedAt: now,
                expiresAt,
                signingKey: senderSigning.privateKey,
                nonce: new Uint8Array(32).fill(1),
                ephemeralKeyPair: suppliedOfferEphemeral,
            }),
        ).resolves.toMatchObject({
            ephemeralKeyPair: suppliedOfferEphemeral,
        });
        await expect(
            createHandshakeOffer({
                transferId: '44444444-4444-4444-8444-444444444444',
                accountEpoch: 4,
                senderDeviceId,
                recipientDeviceId,
                issuedAt: now,
                expiresAt,
                signingKey: senderSigning.privateKey,
                nonce: new Uint8Array(32).fill(2),
                ephemeralKeyPair: suppliedOfferEphemeral,
            }),
        ).rejects.toMatchObject({ code: 'ephemeral_key_reuse' });

        const firstOffer = await createHandshakeOffer({
            transferId: '55555555-5555-4555-8555-555555555555',
            accountEpoch: 4,
            senderDeviceId,
            recipientDeviceId,
            issuedAt: now,
            expiresAt,
            signingKey: senderSigning.privateKey,
            nonce: new Uint8Array(32).fill(3),
        });
        const secondOffer = await createHandshakeOffer({
            transferId: '66666666-6666-4666-8666-666666666666',
            accountEpoch: 4,
            senderDeviceId,
            recipientDeviceId,
            issuedAt: now,
            expiresAt,
            signingKey: senderSigning.privateKey,
            nonce: new Uint8Array(32).fill(4),
        });
        await expect(
            createHandshakeAnswer({
                transferId: firstOffer.core.transfer_id,
                accountEpoch: firstOffer.core.account_epoch,
                senderDeviceId,
                recipientDeviceId,
                issuedAt: now + 1,
                expiresAt,
                signingKey: recipientSigning.privateKey,
                nonce: new Uint8Array(32).fill(5),
                offer: firstOffer,
                ephemeralKeyPair: suppliedAnswerEphemeral,
            }),
        ).resolves.toMatchObject({
            ephemeralKeyPair: suppliedAnswerEphemeral,
        });
        await expect(
            createHandshakeAnswer({
                transferId: secondOffer.core.transfer_id,
                accountEpoch: secondOffer.core.account_epoch,
                senderDeviceId,
                recipientDeviceId,
                issuedAt: now + 1,
                expiresAt,
                signingKey: recipientSigning.privateKey,
                nonce: new Uint8Array(32).fill(6),
                offer: secondOffer,
                ephemeralKeyPair: suppliedAnswerEphemeral,
            }),
        ).rejects.toMatchObject({ code: 'ephemeral_key_reuse' });
    });

    it('creates the same transcript and directional HKDF material on both peers', async () => {
        const senderSigning = await generateP256SigningKeyPair();
        const recipientSigning = await generateP256SigningKeyPair();
        const now = Date.now();
        const offer = await createHandshakeOffer({
            transferId: '44444444-4444-4444-8444-444444444444',
            accountEpoch: 7,
            senderDeviceId: '55555555-5555-4555-8555-555555555555',
            recipientDeviceId: '66666666-6666-4666-8666-666666666666',
            issuedAt: now,
            expiresAt: now + 30_000,
            signingKey: senderSigning.privateKey,
        });
        const answer = await createHandshakeAnswer({
            transferId: offer.core.transfer_id,
            accountEpoch: offer.core.account_epoch,
            senderDeviceId: offer.core.sender_device_id,
            recipientDeviceId: offer.core.recipient_device_id,
            issuedAt: now + 1,
            expiresAt: now + 30_000,
            signingKey: recipientSigning.privateKey,
            offer,
        });

        const senderMaterial = await deriveHandshakeMaterial({
            offer: offer.core,
            answer: answer.core,
            localEphemeralPrivateKey: offer.ephemeralKeyPair.privateKey,
            remoteEphemeralSpki: decodeBase64Url(answer.core.recipient_ephemeral_spki),
            role: 'sender',
        });
        const recipientMaterial = await deriveHandshakeMaterial({
            offer: offer.core,
            answer: answer.core,
            localEphemeralPrivateKey: answer.ephemeralKeyPair.privateKey,
            remoteEphemeralSpki: decodeBase64Url(offer.core.sender_ephemeral_spki),
            role: 'recipient',
        });
        await expect(transcriptHash(offer.core, answer.core)).resolves.toEqual(
            senderMaterial.transcriptHash,
        );
        expect(transcriptBytes(offer.core, answer.core)).toHaveLength(
            'secure-transfer/v1/transcript'.length +
                1 +
                canonicalJsonBytes(offer.core).byteLength +
                1 +
                canonicalJsonBytes(answer.core).byteLength,
        );
        expect(recipientMaterial.transcriptHash).toEqual(senderMaterial.transcriptHash);
        expect(recipientMaterial.s2rNoncePrefix).toEqual(senderMaterial.s2rNoncePrefix);
        expect(recipientMaterial.r2sNoncePrefix).toEqual(senderMaterial.r2sNoncePrefix);
        expect(recipientMaterial.confirmation).toEqual(senderMaterial.confirmation);
        const plaintext = new TextEncoder().encode('same key material');
        const nonce = new Uint8Array(12);
        nonce.set(senderMaterial.s2rNoncePrefix);
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            senderMaterial.s2rKey,
            plaintext,
        );
        await expect(
            crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce },
                recipientMaterial.s2rKey,
                encrypted,
            ),
        ).resolves.toEqual(plaintext.buffer);
    });

    it('encodes bounded headers and authenticates them with AES-GCM', async () => {
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
            'encrypt',
            'decrypt',
        ]);
        const header = {
            v: 1 as const,
            transfer_id: '11111111-1111-4111-8111-111111111111',
            direction: 's2r' as const,
            type: 'confirm' as const,
            counter: 0n,
            plaintext_length: 32,
        };
        const plaintext = new Uint8Array(32).fill(9);
        const frame = await encryptFrame({
            key,
            noncePrefix: Uint8Array.of(1, 2, 3, 4),
            header,
            plaintext,
        });
        expect(frame).toHaveLength(31 + 32 + 16);
        expect(parseFrameHeader(frame.slice(0, 31))).toEqual(header);
        expect(splitFrame(frame).ciphertext).toHaveLength(48);
        await expect(
            decryptFrame({
                key,
                noncePrefix: Uint8Array.of(1, 2, 3, 4),
                frame,
                expectedTransferId: header.transfer_id,
                expectedDirection: 's2r',
                expectedCounter: 0n,
            }),
        ).resolves.toMatchObject({ header, plaintext });
        const tamperedHeader = frame.slice();
        tamperedHeader[18] = 1;
        await expect(
            decryptFrame({ key, noncePrefix: Uint8Array.of(1, 2, 3, 4), frame: tamperedHeader }),
        ).rejects.toThrow(/authentication|direction|length|frame/u);
        expect(frameNonce(Uint8Array.of(1, 2, 3, 4), 7n)).toEqual(
            Uint8Array.of(1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 7),
        );
        expect(() => encodeFrameHeader({ ...header, counter: -1 })).toThrow(/counter/u);
    });

    it('rejects duplicate, skipped, and wrapped counters', () => {
        const counter = new FrameCounter();
        expect(counter.reserve()).toBe(0n);
        expect(counter.reserve()).toBe(1n);
        const received = new FrameCounter();
        expect(() => received.accept(1n)).toThrow(/order/u);
        received.accept(0n);
        expect(() => received.accept(0n)).toThrow(/order/u);
        const last = new FrameCounter((1n << 64n) - 1n);
        expect(last.reserve()).toBe((1n << 64n) - 1n);
        expect(() => last.reserve()).toThrow(/wrap/u);
        const maxReceived = new FrameCounter((1n << 64n) - 1n);
        maxReceived.accept((1n << 64n) - 1n);
        expect(() => maxReceived.accept(0n)).toThrow(/order|counter/u);
    });

    it('requires transcript confirmation before allowing data frames', async () => {
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
            'encrypt',
            'decrypt',
        ]);
        const confirmation = new Uint8Array(32).fill(4);
        const sender = new FrameStream({
            transferId: '77777777-7777-4777-8777-777777777777',
            direction: 's2r',
            confirmation,
        });
        const receiver = new FrameStream({
            transferId: sender.transferId,
            direction: 'r2s',
            confirmation,
        });
        await expect(
            sender.createFrame(key, Uint8Array.of(1, 2, 3, 4), 'manifest', new Uint8Array()),
        ).rejects.toThrow(/Confirmation/u);
        const confirm = await sender.createFrame(
            key,
            Uint8Array.of(1, 2, 3, 4),
            'confirm',
            confirmation,
        );
        await receiver.receiveFrame(key, Uint8Array.of(1, 2, 3, 4), confirm);
        const reverseConfirm = await receiver.createFrame(
            key,
            Uint8Array.of(5, 6, 7, 8),
            'confirm',
            confirmation,
        );
        await sender.receiveFrame(key, Uint8Array.of(5, 6, 7, 8), reverseConfirm);
        const manifest = await sender.createFrame(
            key,
            Uint8Array.of(1, 2, 3, 4),
            'manifest',
            new TextEncoder().encode('manifest'),
        );
        await receiver.receiveFrame(key, Uint8Array.of(1, 2, 3, 4), manifest);
        expect(sender.isConfirmed).toBe(true);
        expect(receiver.isConfirmed).toBe(true);
    });
});
