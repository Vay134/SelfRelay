import { afterEach, describe, expect, it, vi } from 'vitest';

import { PresenceSocketClient } from './presenceClient';

class FakeSocket {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSED = 3;
    readonly sent: string[] = [];
    readyState = FakeSocket.CONNECTING;
    onopen: ((event: Event) => void) | null = null;
    onmessage: ((event: MessageEvent) => void) | null = null;
    onerror: ((event: Event) => void) | null = null;
    onclose: ((event: CloseEvent) => void) | null = null;

    constructor(readonly url: string) {}

    send(value: string): void {
        this.sent.push(value);
    }

    close(): void {
        this.readyState = FakeSocket.CLOSED;
        this.onclose?.({} as CloseEvent);
    }

    open(): void {
        this.readyState = FakeSocket.OPEN;
        this.onopen?.({} as Event);
    }

    message(value: unknown): void {
        this.onmessage?.({ data: JSON.stringify(value) } as MessageEvent);
    }
}

afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
});

describe('PresenceSocketClient', () => {
    it('issues a fresh ticket, heartbeats, parses messages, and reconnects', async () => {
        vi.useFakeTimers();
        vi.stubGlobal('WebSocket', FakeSocket);
        const issueTicket = vi
            .fn()
            .mockResolvedValueOnce({
                ticket: 'ticket-1',
                ticket_id: 'ticket-id-1',
                expires_at: '2026-08-28T00:01:00Z',
            })
            .mockResolvedValueOnce({
                ticket: 'ticket-2',
                ticket_id: 'ticket-id-2',
                expires_at: '2026-08-28T00:01:00Z',
            });
        const sockets: FakeSocket[] = [];
        const messages: unknown[] = [];
        const statuses: string[] = [];
        const socketClient = new PresenceSocketClient({
            issueTicket,
            socketFactory: (url) => {
                const socket = new FakeSocket(url);
                sockets.push(socket);
                return socket as unknown as WebSocket;
            },
            heartbeatIntervalMs: 100,
            reconnectDelayMs: 50,
            onMessage: (message) => messages.push(message),
            onStatusChange: (status) => statuses.push(status),
        });

        const connected = socketClient.connect();
        await vi.waitFor(() => expect(sockets).toHaveLength(1));
        expect(sockets[0]?.url).toContain('ticket=ticket-1');
        sockets[0]?.open();
        await connected;
        vi.advanceTimersByTime(100);
        expect(sockets[0]?.sent).toEqual(['{"type":"heartbeat"}']);
        sockets[0]?.message({ type: 'presence', devices: [] });
        expect(messages).toEqual([{ type: 'presence', devices: [] }]);

        sockets[0]?.close();
        await vi.advanceTimersByTimeAsync(50);
        await vi.waitFor(() => expect(sockets).toHaveLength(2));
        expect(issueTicket).toHaveBeenCalledTimes(2);
        expect(sockets[1]?.url).toContain('ticket=ticket-2');
        sockets[1]?.open();
        await vi.waitFor(() => expect(socketClient.status).toBe('online'));
        socketClient.stop();
        expect(statuses).toEqual(['connecting', 'online', 'reconnecting', 'online', 'idle']);
    });
});
