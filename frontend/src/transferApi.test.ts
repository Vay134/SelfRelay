import { afterEach, describe, expect, it, vi } from 'vitest';

import { clearApiSession, getCurrentSession } from './pairingApi';
import {
    buildIceCandidateEnvelope,
    buildSdpAnswerEnvelope,
    buildSdpOfferEnvelope,
    getTransferPeerDeviceKey,
    issueWebSocketTicket,
    websocketUrl,
    type TransferRequest,
} from './transferApi';

const transfer: TransferRequest = {
    v: 1,
    transfer_id: '11111111-1111-4111-8111-111111111111',
    sender_device_id: '22222222-2222-4222-8222-222222222222',
    recipient_device_id: '33333333-3333-4333-8333-333333333333',
    status: 'accepted',
    created_at: '2026-08-28T00:00:00Z',
    expires_at: '2026-08-28T00:10:00Z',
};

afterEach(() => {
    clearApiSession();
    vi.restoreAllMocks();
});

describe('transfer API boundaries', () => {
    it('fetches only the authenticated transfer peer key', async () => {
        const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
            new Response(
                JSON.stringify({
                    device_id: transfer.recipient_device_id,
                    public_key_spki: 'spki-base64url',
                }),
                { status: 200 },
            ),
        );

        await expect(getTransferPeerDeviceKey(transfer.transfer_id)).resolves.toEqual({
            device_id: transfer.recipient_device_id,
            public_key_spki: 'spki-base64url',
        });
        expect(fetchMock.mock.calls[0]?.[0]).toBe(
            `http://localhost:8000/auth/transfers/${transfer.transfer_id}/peer-key`,
        );
        expect(fetchMock.mock.calls[0]?.[1]?.credentials).toBe('include');
    });

    it('uses the current session CSRF token when issuing a socket ticket', async () => {
        const fetchMock = vi.spyOn(globalThis, 'fetch');
        fetchMock
            .mockResolvedValueOnce(
                new Response(JSON.stringify({ csrf_token: 'csrf-token' }), { status: 200 }),
            )
            .mockResolvedValueOnce(
                new Response(
                    JSON.stringify({
                        ticket: 'one-time-ticket',
                        ticket_id: '44444444-4444-4444-8444-444444444444',
                        expires_at: '2026-08-28T00:01:00Z',
                    }),
                    { status: 200 },
                ),
            );

        await getCurrentSession();
        await issueWebSocketTicket();

        const ticketRequest = fetchMock.mock.calls[1]?.[1];
        expect(new Headers(ticketRequest?.headers).get('X-CSRF-Token')).toBe('csrf-token');
        expect(ticketRequest?.credentials).toBe('include');
    });

    it('builds bounded signaling envelopes with integer expiry fields', () => {
        const now = Date.parse('2026-08-28T00:09:00Z');
        const offer = buildSdpOfferEnvelope(transfer, 'v=0', now);
        const answer = buildSdpAnswerEnvelope(transfer, 'v=0-answer', now);
        const candidate = buildIceCandidateEnvelope(
            transfer,
            {
                candidate: 'candidate:1 1 UDP 1 192.0.2.1 1234 typ host',
                sdpMid: '0',
                sdpMLineIndex: 0,
                usernameFragment: 'fragment',
            },
            now,
        );

        expect(offer).toEqual({
            type: 'sdp_offer',
            v: 1,
            transfer_id: transfer.transfer_id,
            sender_device_id: transfer.sender_device_id,
            recipient_device_id: transfer.recipient_device_id,
            expires_at: now + 30_000,
            sdp: 'v=0',
        });
        expect(answer.type).toBe('sdp_answer');
        expect(answer.expires_at).toBe(now + 30_000);
        expect(candidate.sdp_mline_index).toBe(0);
        expect(Object.keys(candidate)).toEqual([
            'type',
            'v',
            'transfer_id',
            'sender_device_id',
            'recipient_device_id',
            'expires_at',
            'candidate',
            'sdp_mid',
            'sdp_mline_index',
            'username_fragment',
        ]);
    });

    it('maps API origins to the matching WebSocket protocol', () => {
        expect(websocketUrl('ticket value')).toMatch(
            /^ws:\/\/localhost:8000\/auth\/ws\?ticket=ticket%20value$/u,
        );
    });
});
