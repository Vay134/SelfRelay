import { describe, expect, it } from 'vitest';

import fixture from '../../shared/protocol-fixtures/v1.json';
import {
    canonicalJsonBytes,
    decodeBase64Url,
    decryptFrame,
    deriveHandshakeMaterial,
    fingerprintSpki,
    type HandshakeAnswerCore,
    type HandshakeOfferCore,
    importP256Spki,
    parseCanonicalJson,
    parseFrameHeader,
    validateHandshakeOfferCore,
    verifyHandshakeAnswer,
    verifyHandshakeOffer,
} from './transferProtocol';

function asBuffer(value: Uint8Array): ArrayBuffer {
    return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

describe('version 1 protocol fixtures', () => {
    it('reproduces canonical bytes, signatures, and transcript material', async () => {
        const offerCore = fixture.offer_core as HandshakeOfferCore;
        const answerCore = fixture.answer_core as HandshakeAnswerCore;
        const offerBytes = canonicalJsonBytes(offerCore);
        const answerBytes = canonicalJsonBytes(answerCore);
        expect(decodeBase64Url(fixture.canonical_offer_bytes)).toEqual(offerBytes);
        expect(decodeBase64Url(fixture.canonical_answer_bytes)).toEqual(answerBytes);
        expect(parseCanonicalJson(offerBytes)).toEqual(offerCore);
        expect(parseCanonicalJson(answerBytes)).toEqual(answerCore);

        const senderPublicKey = await importP256Spki(
            decodeBase64Url(fixture.sender_signing_public_spki),
        );
        const recipientPublicKey = await importP256Spki(
            decodeBase64Url(fixture.recipient_signing_public_spki),
        );
        await expect(
            fingerprintSpki(decodeBase64Url(fixture.sender_signing_public_spki)),
        ).resolves.toBe(fixture.sender_signing_fingerprint);
        await expect(
            fingerprintSpki(decodeBase64Url(fixture.recipient_signing_public_spki)),
        ).resolves.toBe(fixture.recipient_signing_fingerprint);
        await expect(
            fingerprintSpki(decodeBase64Url(offerCore.sender_ephemeral_spki)),
        ).resolves.toBe(fixture.sender_ephemeral_fingerprint);
        await expect(
            fingerprintSpki(decodeBase64Url(answerCore.recipient_ephemeral_spki)),
        ).resolves.toBe(fixture.recipient_ephemeral_fingerprint);
        const offer = {
            core: offerCore,
            signature: fixture.sender_signature,
        };
        const answer = {
            core: answerCore,
            signature: fixture.recipient_signature,
        };
        await expect(
            verifyHandshakeOffer(offer, senderPublicKey, { now: fixture.now }),
        ).resolves.toBe(true);
        await expect(
            verifyHandshakeAnswer(answer, recipientPublicKey, {
                offer,
                now: fixture.now,
            }),
        ).resolves.toBe(true);

        const senderPrivateKey = await crypto.subtle.importKey(
            'jwk',
            fixture.test_only_ephemeral_private_jwks.sender as JsonWebKey,
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            ['deriveBits'],
        );
        const recipientPrivateKey = await crypto.subtle.importKey(
            'jwk',
            fixture.test_only_ephemeral_private_jwks.recipient as JsonWebKey,
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            ['deriveBits'],
        );
        const senderMaterial = await deriveHandshakeMaterial({
            offer: offerCore,
            answer: answerCore,
            localEphemeralPrivateKey: senderPrivateKey,
            remoteEphemeralSpki: decodeBase64Url(answerCore.recipient_ephemeral_spki),
            role: 'sender',
        });
        const recipientMaterial = await deriveHandshakeMaterial({
            offer: offerCore,
            answer: answerCore,
            localEphemeralPrivateKey: recipientPrivateKey,
            remoteEphemeralSpki: decodeBase64Url(offerCore.sender_ephemeral_spki),
            role: 'recipient',
        });
        expect(senderMaterial.transcriptHash).toEqual(decodeBase64Url(fixture.transcript_hash));
        expect(recipientMaterial.transcriptHash).toEqual(senderMaterial.transcriptHash);
        expect(senderMaterial.s2rNoncePrefix).toEqual(decodeBase64Url(fixture.s2r_nonce_prefix));
        expect(senderMaterial.r2sNoncePrefix).toEqual(decodeBase64Url(fixture.r2s_nonce_prefix));
        expect(senderMaterial.confirmation).toEqual(decodeBase64Url(fixture.confirmation));
        expect(recipientMaterial.s2rNoncePrefix).toEqual(senderMaterial.s2rNoncePrefix);
        expect(recipientMaterial.r2sNoncePrefix).toEqual(senderMaterial.r2sNoncePrefix);
        expect(recipientMaterial.confirmation).toEqual(senderMaterial.confirmation);

        const receiverStreamKey = senderMaterial.s2rKey;
        const confirmation = await decryptFrame({
            key: receiverStreamKey,
            noncePrefix: senderMaterial.s2rNoncePrefix,
            frame: decodeBase64Url(fixture.confirmation_frame),
            expectedTransferId: offerCore.transfer_id,
            expectedDirection: 's2r',
            expectedCounter: 0n,
        });
        expect(confirmation.plaintext).toEqual(decodeBase64Url(fixture.confirmation));
        const manifest = await decryptFrame({
            key: receiverStreamKey,
            noncePrefix: senderMaterial.s2rNoncePrefix,
            frame: decodeBase64Url(fixture.manifest_frame),
            expectedTransferId: offerCore.transfer_id,
            expectedDirection: 's2r',
            expectedCounter: 1n,
        });
        expect(manifest.plaintext).toEqual(decodeBase64Url(fixture.manifest_plaintext));
    });

    it('rejects expired, extra-field, tampered-signature, and malformed-frame fixtures', async () => {
        const offerCore = fixture.offer_core as HandshakeOfferCore;
        expect(() =>
            validateHandshakeOfferCore(fixture.invalid.expired_offer_core, fixture.now),
        ).toThrow(/expired/u);
        const senderPublicKey = await importP256Spki(
            decodeBase64Url(fixture.sender_signing_public_spki),
        );
        await expect(
            verifyHandshakeOffer(
                {
                    core: fixture.invalid.extra_offer_field as unknown as HandshakeOfferCore,
                    signature: fixture.sender_signature,
                },
                senderPublicKey,
                { now: fixture.now },
            ),
        ).resolves.toBe(false);
        await expect(
            verifyHandshakeOffer(
                { core: offerCore, signature: fixture.invalid.tampered_sender_signature },
                senderPublicKey,
                { now: fixture.now },
            ),
        ).resolves.toBe(false);
        expect(() =>
            parseFrameHeader(decodeBase64Url(fixture.invalid.unknown_version_frame).slice(0, 31)),
        ).toThrow(/unsupported/u);
        expect(() =>
            parseFrameHeader(decodeBase64Url(fixture.invalid.oversized_frame_header)),
        ).toThrow(/length/u);
        await expect(
            decryptFrame({
                key: await crypto.subtle.importKey(
                    'raw',
                    asBuffer(decodeBase64Url(fixture.s2r_key)),
                    { name: 'AES-GCM' },
                    false,
                    ['decrypt'],
                ),
                noncePrefix: decodeBase64Url(fixture.s2r_nonce_prefix),
                frame: decodeBase64Url(fixture.invalid.tampered_frame),
            }),
        ).rejects.toThrow(/authentication/u);
    });
});
