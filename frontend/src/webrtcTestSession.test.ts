import { describe, expect, it, vi } from 'vitest';

import {
    buildIceCandidateEnvelope,
    buildSdpOfferEnvelope,
    type SignalingEnvelope,
    type TransferRequest,
} from './transferApi';
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
}

function fakeFactory(connection: FakePeerConnection) {
    return () => connection as unknown as RTCPeerConnection;
}

describe('WebRtcTestSession', () => {
    it('creates a sender data channel and sends the documented SDP offer envelope', async () => {
        const connection = new FakePeerConnection();
        const signals: SignalingEnvelope[] = [];
        const session = new WebRtcTestSession({
            transfer,
            role: 'sender',
            peerConnectionFactory: fakeFactory(connection),
            sendSignal: (message) => {
                signals.push(message);
            },
        });

        await session.start();

        expect(connection.channels[0]?.label).toBe('secure-transfer-test');
        expect(signals).toHaveLength(1);
        expect(signals[0]).toEqual(
            expect.objectContaining({
                type: 'sdp_offer',
                v: 1,
                transfer_id: transfer.transfer_id,
                sender_device_id: transfer.sender_device_id,
                recipient_device_id: transfer.recipient_device_id,
                sdp: 'v=0\r\no=sender',
            }),
        );

        connection.openChannel();
        expect(session.state).toBe('connected');
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
});
