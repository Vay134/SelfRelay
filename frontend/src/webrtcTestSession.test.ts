import { describe, expect, it, vi } from 'vitest';

import {
    buildIceCandidateEnvelope,
    buildSdpOfferEnvelope,
    type SignalingEnvelope,
    type TransferRequest,
} from './transferApi';
import { generateP256SigningKeyPair } from './transferProtocol';
import { WebRtcTestSession } from './webrtcTestSession';

const transfer: TransferRequest = {
    v: 1,
    transfer_id: '11111111-1111-4111-8111-111111111111',
    sender_device_id: '22222222-2222-4222-8222-222222222222',
    recipient_device_id: '33333333-3333-4333-8333-333333333333',
    status: 'accepted',
    created_at: '2026-08-28T00:00:00Z',
    expires_at: '2026-08-28T00:10:00Z',
};

class FakeDataChannel {
    readonly label: string;
    onopen: (() => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: (() => void) | null = null;
    readyState = 'connecting';

    constructor(label: string) {
        this.label = label;
    }

    close(): void {
        this.readyState = 'closed';
        this.onclose?.();
    }
}

class FakePeerConnection {
    localDescription: RTCSessionDescriptionInit | null = null;
    connectionState: RTCPeerConnectionState = 'new';
    onicecandidate: ((event: RTCPeerConnectionIceEvent) => void) | null = null;
    ondatachannel: ((event: RTCDataChannelEvent) => void) | null = null;
    onconnectionstatechange: (() => void) | null = null;
    readonly addedCandidates: RTCIceCandidateInit[] = [];
    readonly channels: FakeDataChannel[] = [];
    readonly setRemoteDescriptionMock = vi.fn();
    readonly stats = new Map<string, object>();

    createDataChannel(label: string): RTCDataChannel {
        const channel = new FakeDataChannel(label);
        this.channels.push(channel);
        return channel as unknown as RTCDataChannel;
    }

    async createOffer(): Promise<RTCSessionDescriptionInit> {
        return { type: 'offer', sdp: 'v=0\r\no=sender' };
    }

    async createAnswer(): Promise<RTCSessionDescriptionInit> {
        return { type: 'answer', sdp: 'v=0\r\no=recipient' };
    }

    async setLocalDescription(description: RTCSessionDescriptionInit): Promise<void> {
        this.localDescription = description;
    }

    async setRemoteDescription(description: RTCSessionDescriptionInit): Promise<void> {
        this.setRemoteDescriptionMock(description);
    }

    async addIceCandidate(candidate: RTCIceCandidateInit): Promise<void> {
        this.addedCandidates.push(candidate);
    }

    async getStats(): Promise<RTCStatsReport> {
        return this.stats as unknown as RTCStatsReport;
    }

    close(): void {
        this.connectionState = 'closed';
        this.onconnectionstatechange?.();
    }

    openChannel(): void {
        const channel = this.channels[0];
        if (channel) {
            channel.readyState = 'open';
            channel.onopen?.();
        }
    }

    receiveChannel(channel: FakeDataChannel): void {
        this.ondatachannel?.({ channel } as RTCDataChannelEvent);
    }
}

function fakeFactory(connection: FakePeerConnection) {
    return () => connection as unknown as RTCPeerConnection;
}

describe('WebRtcTestSession', () => {
    it('creates an authenticated sender handshake offer', async () => {
        const connection = new FakePeerConnection();
        const signals: SignalingEnvelope[] = [];
        const signingKeyPair = await generateP256SigningKeyPair(true);
        const senderTransfer: TransferRequest = {
            ...transfer,
            expires_at: new Date(Date.now() + 60_000).toISOString(),
        };
        const session = new WebRtcTestSession({
            transfer: senderTransfer,
            role: 'sender',
            peerConnectionFactory: fakeFactory(connection),
            sendSignal: (message) => {
                signals.push(message);
            },
            signingKey: signingKeyPair.privateKey,
            peerSigningPublicKey: signingKeyPair.publicKey,
            accountEpoch: 0,
        });

        await session.start();

        expect(signals).toHaveLength(1);
        expect(signals[0]).toEqual(
            expect.objectContaining({
                type: 'handshake_offer',
                v: 1,
                transfer_id: transfer.transfer_id,
                sender_device_id: transfer.sender_device_id,
                recipient_device_id: transfer.recipient_device_id,
            }),
        );
        expect(connection.channels).toHaveLength(0);
    });

    it('queues ICE until the remote description, then answers an SDP offer', async () => {
        const connection = new FakePeerConnection();
        const signals: SignalingEnvelope[] = [];
        const session = new WebRtcTestSession({
            transfer,
            role: 'recipient',
            peerConnectionFactory: fakeFactory(connection),
            sendSignal: (message) => {
                signals.push(message);
            },
        });
        const candidate = buildIceCandidateEnvelope(transfer, {
            candidate: 'candidate:1 1 UDP 1 192.0.2.1 1234 typ host',
            sdpMid: '0',
            sdpMLineIndex: 0,
        });
        const offer = buildSdpOfferEnvelope(transfer, 'v=0\r\no=sender');

        await session.handleSignal(candidate);
        expect(connection.addedCandidates).toHaveLength(0);
        await session.handleSignal(offer);

        expect(connection.addedCandidates).toEqual([
            {
                candidate: candidate.candidate,
                sdpMid: '0',
                sdpMLineIndex: 0,
                usernameFragment: undefined,
            },
        ]);
        expect(signals).toHaveLength(1);
        expect(signals[0]).toEqual(
            expect.objectContaining({ type: 'sdp_answer', sdp: 'v=0\r\no=recipient' }),
        );
    });

    it('reports an injected remote DataChannel through the testable peer seam', () => {
        const connection = new FakePeerConnection();
        let received: RTCDataChannel | null = null;
        const session = new WebRtcTestSession({
            transfer,
            role: 'recipient',
            peerConnectionFactory: fakeFactory(connection),
            sendSignal: () => undefined,
            onDataChannel: (channel) => {
                received = channel;
            },
        });
        const channel = new FakeDataChannel('secure-transfer-test');

        connection.receiveChannel(channel);
        channel.readyState = 'open';
        channel.onopen?.();

        expect(received).toBe(channel);
        expect(session.state).toBe('connected');
    });

    it('reports the selected ICE pair as relayed without exposing candidate details', async () => {
        const connection = new FakePeerConnection();
        connection.stats.set('pair', {
            type: 'candidate-pair',
            state: 'succeeded',
            selected: true,
            localCandidateId: 'local',
            remoteCandidateId: 'remote',
        });
        connection.stats.set('local', { type: 'local-candidate', candidateType: 'relay' });
        connection.stats.set('remote', { type: 'remote-candidate', candidateType: 'srflx' });
        const relayStatuses: string[] = [];
        const session = new WebRtcTestSession({
            transfer,
            role: 'recipient',
            peerConnectionFactory: fakeFactory(connection),
            sendSignal: () => undefined,
            onRelayStatusChange: (status) => relayStatuses.push(status),
        });
        const channel = new FakeDataChannel('secure-transfer-test');

        connection.receiveChannel(channel);
        channel.readyState = 'open';
        channel.onopen?.();
        await Promise.resolve();

        expect(session.relayStatus).toBe('relay');
        expect(relayStatuses).toEqual(['relay']);
    });
});
