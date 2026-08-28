import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiError, API_REQUEST_TIMEOUT_MS, apiRequest } from './pairingApi';
import { PresenceSocketClient, type PresenceClientStatus } from './presenceClient';
import {
    buildIceCandidateEnvelope,
    getTransferTurnCredentials,
    type TransferRequest,
} from './transferApi';
import {
    DEFAULT_NEGOTIATION_TIMEOUT_MS,
    MAX_PENDING_ICE_CANDIDATES,
    WebRtcTestSession,
} from './webrtcTestSession';

const transfer: TransferRequest = {
    v: 1,
    transfer_id: '11111111-1111-4111-8111-111111111111',
    sender_device_id: '22222222-2222-4222-8222-222222222222',
    recipient_device_id: '33333333-3333-4333-8333-333333333333',
    status: 'accepted',
    created_at: '2026-08-28T00:00:00Z',
    expires_at: '2026-08-28T00:10:00Z',
};

class SilentPeerConnection {
    localDescription: RTCSessionDescriptionInit | null = null;
    onicecandidate: ((event: RTCPeerConnectionIceEvent) => void) | null = null;
    ondatachannel: ((event: RTCDataChannelEvent) => void) | null = null;
    onconnectionstatechange: (() => void) | null = null;
    connectionState: RTCPeerConnectionState = 'new';

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

function silentFactory(): () => RTCPeerConnection {
    return () => new SilentPeerConnection() as unknown as RTCPeerConnection;
}

afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
});

describe('bounded browser retries', () => {
    it('stops reconnecting and reports a terminal failure after the attempt budget', async () => {
        vi.useFakeTimers();
        const statuses: PresenceClientStatus[] = [];
        let attempts = 0;
        const client = new PresenceSocketClient({
            issueTicket: async () => ({
                ticket: 'ticket',
                ticket_id: 'ticket-id',
                expires_at: '2026-08-28T00:01:00Z',
            }),
            socketFactory: () => {
                attempts += 1;
                throw new Error('The presence socket could not connect.');
            },
            reconnectDelayMs: 1,
            maxReconnectAttempts: 3,
            onError: () => undefined,
            onStatusChange: (status) => statuses.push(status),
        });

        await client.connect().catch(() => undefined);
        for (let tick = 0; tick < 6; tick += 1) {
            await vi.advanceTimersByTimeAsync(2);
        }

        expect(statuses.at(-1)).toBe('failed');
        expect(attempts).toBe(4);
        client.stop();
    });

    it('aborts a hanging API request with a safe timeout message', async () => {
        vi.useFakeTimers();
        vi.stubGlobal(
            'fetch',
            vi.fn(
                (_url: string, init?: RequestInit) =>
                    new Promise<Response>((_resolve, reject) => {
                        init?.signal?.addEventListener('abort', () =>
                            reject(new DOMException('aborted', 'AbortError')),
                        );
                    }),
            ),
        );

        const pending = apiRequest('/auth/session').catch((error: unknown) => error);
        await vi.advanceTimersByTimeAsync(API_REQUEST_TIMEOUT_MS + 10);
        const error = await pending;

        expect(error).toBeInstanceOf(ApiError);
        expect((error as ApiError).message).toBe(
            'The secure transfer service did not respond in time.',
        );
        expect((error as ApiError).message).not.toContain('AbortError');
    });
});

describe('terminal TURN failures', () => {
    it('surfaces an unavailable TURN provider as a bounded API error', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn(
                async () =>
                    new Response(
                        JSON.stringify({ detail: 'TURN credentials are temporarily unavailable.' }),
                        { status: 503, headers: { 'Content-Type': 'application/json' } },
                    ),
            ),
        );

        const failure = await getTransferTurnCredentials(transfer.transfer_id).catch(
            (error: unknown) => error,
        );

        expect(failure).toBeInstanceOf(ApiError);
        expect((failure as ApiError).status).toBe(503);
        expect((failure as ApiError).message).toBe('TURN credentials are temporarily unavailable.');
    });
});

describe('bounded negotiation state', () => {
    it('rejects ICE candidates past the pending queue limit', async () => {
        const session = new WebRtcTestSession({
            transfer,
            role: 'recipient',
            peerConnectionFactory: silentFactory(),
            sendSignal: () => undefined,
        });
        const candidate = buildIceCandidateEnvelope(transfer, {
            candidate: 'candidate:1 1 UDP 1 192.0.2.1 1234 typ host',
            sdpMid: '0',
            sdpMLineIndex: 0,
        });

        for (let index = 0; index < MAX_PENDING_ICE_CANDIDATES; index += 1) {
            await session.handleSignal(candidate);
        }

        await expect(session.handleSignal(candidate)).rejects.toThrow(
            'The ICE candidate queue is full.',
        );
    });

    it('fails a negotiation that never connects within its timeout', async () => {
        vi.useFakeTimers();
        const states: string[] = [];
        const session = new WebRtcTestSession({
            transfer: { ...transfer, expires_at: new Date(Date.now() + 600_000).toISOString() },
            role: 'recipient',
            peerConnectionFactory: silentFactory(),
            sendSignal: () => undefined,
            onStateChange: (state) => states.push(state),
        });

        await session.start();
        await vi.advanceTimersByTimeAsync(DEFAULT_NEGOTIATION_TIMEOUT_MS + 10);

        expect(session.state).toBe('failed');
        expect(states).toEqual(['negotiating', 'failed']);
    });
});
