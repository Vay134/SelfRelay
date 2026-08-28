import { describe, expect, it } from 'vitest';

import {
    FrameCounter,
    FrameStream,
    canonicalJson,
    decodeBase64Url,
    encodeBase64Url,
    frameNonce,
    parseFrameHeader,
    parseStrictJson,
} from './transferProtocol';

function deterministicBytes(length: number, seed: number): Uint8Array {
    const output = new Uint8Array(length);
    let value = seed >>> 0;
    for (let index = 0; index < length; index += 1) {
        value ^= value << 13;
        value ^= value >>> 17;
        value ^= value << 5;
        output[index] = value & 0xff;
    }
    return output;
}

describe('transfer protocol robustness properties', () => {
    it('round-trips many byte sequences and keeps every counter nonce unique', () => {
        const nonces = new Set<string>();
        for (let length = 0; length <= 96; length += 1) {
            const bytes = deterministicBytes(length, 0x12345678 + length);
            const encoded = encodeBase64Url(bytes);
            expect(decodeBase64Url(encoded)).toEqual(bytes);
        }
        for (let counter = 0n; counter < 2048n; counter += 1n) {
            nonces.add(encodeBase64Url(frameNonce(Uint8Array.of(9, 8, 7, 6), counter)));
        }
        expect(nonces).toHaveLength(2048);
    });

    it('terminates malformed JSON and frame headers with protocol errors', () => {
        const malformedJson = [
            '',
            '{',
            '[1,',
            '{"x":1,"x":2}',
            '{"x":01}',
            '{"x":"\\u00"}',
            '{"x":true trailing}',
            'null null',
        ];
        for (const value of malformedJson) {
            expect(() => parseStrictJson(value)).toThrow();
        }
        for (let length = 0; length <= 64; length += 1) {
            const bytes = deterministicBytes(length, 0xabcdef + length);
            try {
                parseFrameHeader(bytes);
            } catch (error) {
                expect(error).toMatchObject({ name: 'ProtocolError' });
            }
        }
        expect(canonicalJson({ stable: true })).toBe('{"stable":true}');
    });

    it('does not advance a receive counter after an unauthenticated frame', async () => {
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
            'encrypt',
            'decrypt',
        ]);
        const confirmation = new Uint8Array(32).fill(3);
        const sender = new FrameStream({
            transferId: '88888888-8888-4888-8888-888888888888',
            direction: 's2r',
            confirmation,
        });
        const receiver = new FrameStream({
            transferId: sender.transferId,
            direction: 'r2s',
            confirmation,
        });
        const frame = await sender.createFrame(
            key,
            Uint8Array.of(1, 2, 3, 4),
            'confirm',
            confirmation,
        );
        const tampered = frame.slice();
        tampered[tampered.length - 1] ^= 1;
        await expect(
            receiver.receiveFrame(key, Uint8Array.of(1, 2, 3, 4), tampered),
        ).rejects.toThrow(/authentication/u);
        expect(receiver.nextReceiveCounter).toBe(0n);
        await receiver.receiveFrame(key, Uint8Array.of(1, 2, 3, 4), frame);
        expect(receiver.nextReceiveCounter).toBe(1n);
        await expect(receiver.receiveFrame(key, Uint8Array.of(1, 2, 3, 4), frame)).rejects.toThrow(
            /order|state|confirmation/u,
        );

        const counters = new FrameCounter(2048);
        expect(counters.next).toBe(2048n);
        expect(() => counters.accept(2047)).toThrow(/order/u);
    });
});
