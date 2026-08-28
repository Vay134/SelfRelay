import { describe, expect, it, vi } from 'vitest';

import { FileTransferEngine, type TransferDataChannel } from './fileTransfer';
import { rtcConfigurationFromTurnCredentials } from './rtcConfiguration';
import { createRelayOnlyRtcConfiguration } from './testRelayConfiguration';
import type { SignalingEnvelope, TransferRequest, TurnCredentials } from './transferApi';
import { generateP256SigningKeyPair } from './transferProtocol';
import { WebRtcTestSession } from './webrtcTestSession';

const CREDENTIALS: TurnCredentials = {
    ice_servers: [
        {
            urls: ['stun:turn.test.invalid', 'turn:turn.test.invalid?transport=udp'],
            username: 'turn-user',
            credential: 'turn-credential',
        },
    ],
    expires_at: 1_800_000_000_000,
};

const FILE_CONTENT = 'relay-and-direct-must-match';

function transfer(): TransferRequest {
    return {
        v: 1,
        transfer_id: '11111111-1111-4111-8111-111111111111',
        sender_device_id: '22222222-2222-4222-8222-222222222222',
        recipient_device_id: '33333333-3333-4333-8333-333333333333',
        status: 'accepted',
        created_at: '2026-08-28T00:00:00Z',
        expires_at: new Date(Date.now() + 600_000).toISOString(),
    };
}

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
        const peer = this.peer;
        if (peer?.onmessage) {
            queueMicrotask(() => peer.onmessage?.({ data } as MessageEvent));
        }
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

class RecordingPeerConnection {
    static readonly configurations: (RTCConfiguration | undefined)[] = [];
    onicecandidate: ((event: RTCPeerConnectionIceEvent) => void) | null = null;
    ondatachannel: ((event: RTCDataChannelEvent) => void) | null = null;
    onconnectionstatechange: (() => void) | null = null;
    connectionState: RTCPeerConnectionState = 'new';

    constructor(configuration?: RTCConfiguration) {
        RecordingPeerConnection.configurations.push(configuration);
    }

    createDataChannel(): RTCDataChannel {
        return { close: () => undefined } as unknown as RTCDataChannel;
    }

    async createOffer(): Promise<RTCSessionDescriptionInit> {
        return { type: 'offer', sdp: 'v=0' };
    }

    async createAnswer(): Promise<RTCSessionDescriptionInit> {
        return { type: 'answer', sdp: 'v=0' };
    }

    async setLocalDescription(): Promise<void> {}
    async setRemoteDescription(): Promise<void> {}
    async addIceCandidate(): Promise<void> {}
    close(): void {}
}

type TransferOutcome = {
    receiptStatus: string;
    recipientState: string;
    fileName: string | undefined;
    mediaType: string | undefined;
    content: string;
    progress: number[];
    frameCount: number;
};

/** Run one authenticated handshake and file transfer under `configuration`. */
async function runTransfer(configuration: RTCConfiguration): Promise<TransferOutcome> {
    const request = transfer();
    const [senderKeys, recipientKeys] = await Promise.all([
        generateP256SigningKeyPair(true),
        generateP256SigningKeyPair(true),
    ]);
    let recipientSession: WebRtcTestSession | null = null;
    const sender = new WebRtcTestSession({
        transfer: request,
        role: 'sender',
        rtcConfiguration: configuration,
        peerConnectionFactory: (config) =>
            new RecordingPeerConnection(config) as unknown as RTCPeerConnection,
        sendSignal: (message: SignalingEnvelope) => {
            void recipientSession?.handleSignal(message);
        },
        signingKey: senderKeys.privateKey,
        peerSigningPublicKey: recipientKeys.publicKey,
        accountEpoch: 0,
    });
    recipientSession = new WebRtcTestSession({
        transfer: request,
        role: 'recipient',
        rtcConfiguration: configuration,
        peerConnectionFactory: (config) =>
            new RecordingPeerConnection(config) as unknown as RTCPeerConnection,
        sendSignal: (message: SignalingEnvelope) => {
            void sender.handleSignal(message);
        },
        signingKey: recipientKeys.privateKey,
        peerSigningPublicKey: senderKeys.publicKey,
        accountEpoch: 0,
    });

    await sender.start();
    await vi.waitFor(() => expect(sender.material).not.toBeNull());
    const material = sender.material;
    if (!material || !recipientSession.material) {
        throw new Error('The authenticated handshake did not derive shared material.');
    }

    const [senderChannel, recipientChannel] = channelPair();
    const progress: number[] = [];
    const senderEngine = new FileTransferEngine({
        channel: senderChannel,
        transferId: request.transfer_id,
        role: 'sender',
        material,
        signingKey: senderKeys.privateKey,
        chunkSize: 8,
        onProgress: ({ bytesTransferred }) => progress.push(bytesTransferred),
    });
    const recipientEngine = new FileTransferEngine({
        channel: recipientChannel,
        transferId: request.transfer_id,
        role: 'recipient',
        material: recipientSession.material,
        senderSigningPublicKey: senderKeys.publicKey,
    });
    senderChannel.open();
    recipientChannel.open();

    const receipt = await senderEngine.sendFile(
        new Blob([FILE_CONTENT], { type: 'text/plain' }),
        'relay.txt',
    );

    return {
        receiptStatus: receipt.status,
        recipientState: recipientEngine.state,
        fileName: recipientEngine.receivedFile?.fileName,
        mediaType: recipientEngine.receivedFile?.mediaType,
        content: (await recipientEngine.receivedFile?.blob.text()) ?? '',
        progress,
        frameCount: senderChannel.sent.length,
    };
}

describe('forced-relay transfers', () => {
    it('uses relay-only ICE while keeping the direct configuration otherwise identical', () => {
        const direct = rtcConfigurationFromTurnCredentials(CREDENTIALS);
        const relay = createRelayOnlyRtcConfiguration(CREDENTIALS);

        expect(relay.iceTransportPolicy).toBe('relay');
        expect(direct.iceTransportPolicy).toBeUndefined();
        expect({ ...relay, iceTransportPolicy: undefined }).toEqual({
            ...direct,
            iceTransportPolicy: undefined,
        });
    });

    it('passes the same integrity, ordering, and completion checks as a direct transfer', async () => {
        RecordingPeerConnection.configurations.length = 0;

        const direct = await runTransfer(rtcConfigurationFromTurnCredentials(CREDENTIALS));
        const relay = await runTransfer(createRelayOnlyRtcConfiguration(CREDENTIALS));

        expect(relay).toEqual(direct);
        expect(relay.receiptStatus).toBe('verified');
        expect(relay.recipientState).toBe('completed');
        expect(relay.content).toBe(FILE_CONTENT);
        expect(
            RecordingPeerConnection.configurations
                .slice(2)
                .every((configuration) => configuration?.iceTransportPolicy === 'relay'),
        ).toBe(true);
    });
});
