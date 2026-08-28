import { describe, expect, it } from 'vitest';

import {
    FileTransferEngine,
    IncrementalSha256,
    MAX_TRANSFER_BYTES,
    sanitizeFileName,
    type TransferDataChannel,
} from './fileTransfer';
import { encodeBase64Url } from './transferProtocol';

class FakeChannel implements TransferDataChannel {
    readyState = 'connecting';
    bufferedAmount = 0;
    bufferedAmountLowThreshold = 0;
    binaryType: BinaryType = 'arraybuffer';
    onopen: (() => void) | null = null;
    onmessage: ((event: MessageEvent) => void) | null = null;
    onerror: ((event: Event) => void) | null = null;
    onclose: (() => void) | null = null;
    onbufferedamountlow: (() => void) | null = null;
    peer: FakeChannel | null = null;
    readonly sent: ArrayBuffer[] = [];

    send(data: ArrayBuffer): void {
        this.sent.push(data.slice(0));
        this.bufferedAmount += data.byteLength;
        const peer = this.peer;
        if (peer?.onmessage) {
            queueMicrotask(() => peer.onmessage?.({ data } as MessageEvent));
        }
        this.bufferedAmount = 0;
        this.onbufferedamountlow?.();
    }

    close(): void {
        this.readyState = 'closed';
        this.onclose?.();
    }

    open(): void {
        this.readyState = 'open';
        this.onopen?.();
    }
}

function channelPair(): [FakeChannel, FakeChannel] {
    const sender = new FakeChannel();
    const recipient = new FakeChannel();
    sender.peer = recipient;
    recipient.peer = sender;
    return [sender, recipient];
}

async function material(): Promise<{
    confirmation: Uint8Array;
    transcriptHash: Uint8Array;
    s2rKey: CryptoKey;
    r2sKey: CryptoKey;
    s2rNoncePrefix: Uint8Array;
    r2sNoncePrefix: Uint8Array;
}> {
    const [s2rKey, r2sKey] = await Promise.all([
        crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
        crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
    ]);
    return {
        confirmation: new Uint8Array(32).fill(7),
        transcriptHash: new Uint8Array(32).fill(8),
        s2rKey: s2rKey as CryptoKey,
        r2sKey: r2sKey as CryptoKey,
        s2rNoncePrefix: new Uint8Array([1, 2, 3, 4]),
        r2sNoncePrefix: new Uint8Array([5, 6, 7, 8]),
    };
}

describe('IncrementalSha256', () => {
    it('matches SHA-256 when input arrives in irregular pieces', async () => {
        const hash = new IncrementalSha256();
        hash.update(new TextEncoder().encode('a'));
        hash.update(new TextEncoder().encode('bc'.repeat(100)));
        expect(encodeBase64Url(hash.digest())).toBe(
            encodeBase64Url(
                new Uint8Array(
                    await crypto.subtle.digest(
                        'SHA-256',
                        new TextEncoder().encode(`a${'bc'.repeat(100)}`),
                    ),
                ),
            ),
        );
    });
});

describe('FileTransferEngine', () => {
    it('confirms, transfers bounded chunks, verifies completion, and returns a receipt', async () => {
        const [senderChannel, recipientChannel] = channelPair();
        const keys = await material();
        const senderSigning = (await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['sign', 'verify'],
        )) as CryptoKeyPair;
        const progress: number[] = [];
        const sender = new FileTransferEngine({
            channel: senderChannel,
            transferId: '11111111-1111-4111-8111-111111111111',
            role: 'sender',
            material: keys,
            signingKey: senderSigning.privateKey,
            chunkSize: 4,
            onProgress: ({ bytesTransferred }) => progress.push(bytesTransferred),
        });
        const recipient = new FileTransferEngine({
            channel: recipientChannel,
            transferId: '11111111-1111-4111-8111-111111111111',
            role: 'recipient',
            material: keys,
            senderSigningPublicKey: senderSigning.publicKey,
        });
        senderChannel.open();
        recipientChannel.open();
        const receiptPromise = sender.sendFile(
            new Blob(['abcdefghij'], { type: 'text/plain' }),
            '../../safe.txt',
        );
        const receipt = await receiptPromise;
        expect(receipt.status).toBe('verified');
        expect(recipient.state).toBe('completed');
        expect(recipient.receivedFile?.fileName).toBe('safe.txt');
        expect(recipient.receivedFile?.mediaType).toBe('text/plain');
        await expect(recipient.receivedFile?.blob.text()).resolves.toBe('abcdefghij');
        expect(progress).toEqual([4, 8, 10]);
        expect(senderChannel.sent.length).toBe(1 + 1 + 3 + 1);
    });

    it('rejects a file above the 250 MB limit before sending metadata', async () => {
        const [senderChannel] = channelPair();
        const keys = await material();
        const signing = (await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['sign', 'verify'],
        )) as CryptoKeyPair;
        const sender = new FileTransferEngine({
            channel: senderChannel,
            transferId: '22222222-2222-4222-8222-222222222222',
            role: 'sender',
            material: keys,
            signingKey: signing.privateKey,
        });
        const oversized = {
            size: MAX_TRANSFER_BYTES + 1,
            slice: () => new Blob(),
        } as unknown as Blob;
        await expect(sender.sendFile(oversized)).rejects.toMatchObject({ code: 'file_too_large' });
        expect(senderChannel.sent).toHaveLength(0);
    });
});

it('sanitizes path components, control characters, and reserved names', () => {
    expect(sanitizeFileName('C:\\temp\\CON.txt\u0000')).toBe('_CON.txt');
    expect(sanitizeFileName('../../')).toBe('download');
});
