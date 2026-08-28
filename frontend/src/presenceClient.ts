import {
    issueWebSocketTicket,
    parseSocketMessage,
    websocketUrl,
    type PresenceSocketMessage,
} from './transferApi';

export type PresenceClientStatus =
    | 'idle'
    | 'connecting'
    | 'online'
    | 'reconnecting'
    | 'offline'
    | 'failed';

export type WebSocketFactory = (url: string) => WebSocket;

export type PresenceSocketClientOptions = {
    issueTicket?: typeof issueWebSocketTicket;
    socketFactory?: WebSocketFactory;
    heartbeatIntervalMs?: number;
    reconnectDelayMs?: number;
    maxReconnectAttempts?: number;
    onMessage?: (message: PresenceSocketMessage) => void;
    onStatusChange?: (status: PresenceClientStatus) => void;
    onError?: (error: unknown) => void;
};

const DEFAULT_HEARTBEAT_INTERVAL_MS = 15_000;
const DEFAULT_RECONNECT_DELAY_MS = 1_000;
const DEFAULT_MAX_RECONNECT_ATTEMPTS = 5;
const WEBSOCKET_CONNECTING = 0;
const WEBSOCKET_OPEN = 1;

export class PresenceSocketClient {
    private readonly issueTicket: typeof issueWebSocketTicket;
    private readonly socketFactory: WebSocketFactory;
    private readonly heartbeatIntervalMs: number;
    private readonly reconnectDelayMs: number;
    private readonly maxReconnectAttempts: number;
    private readonly onMessage?: (message: PresenceSocketMessage) => void;
    private readonly onStatusChange?: (status: PresenceClientStatus) => void;
    private readonly onError?: (error: unknown) => void;
    private socket: WebSocket | null = null;
    private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
    private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    private openingPromise: Promise<void> | null = null;
    private running = false;
    private hasConnected = false;
    private reconnectAttempts = 0;
    private currentStatus: PresenceClientStatus = 'idle';

    constructor(options: PresenceSocketClientOptions = {}) {
        this.issueTicket = options.issueTicket ?? issueWebSocketTicket;
        this.socketFactory = options.socketFactory ?? ((url) => new WebSocket(url));
        this.heartbeatIntervalMs = options.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_INTERVAL_MS;
        this.reconnectDelayMs = options.reconnectDelayMs ?? DEFAULT_RECONNECT_DELAY_MS;
        this.maxReconnectAttempts = options.maxReconnectAttempts ?? DEFAULT_MAX_RECONNECT_ATTEMPTS;
        if (!Number.isSafeInteger(this.maxReconnectAttempts) || this.maxReconnectAttempts <= 0) {
            throw new TypeError('The maximum reconnect attempts must be positive.');
        }
        this.onMessage = options.onMessage;
        this.onStatusChange = options.onStatusChange;
        this.onError = options.onError;
    }

    get status(): PresenceClientStatus {
        return this.currentStatus;
    }

    start(): void {
        if (this.running) {
            return;
        }
        this.running = true;
        this.setStatus(this.hasConnected ? 'reconnecting' : 'connecting');
        void this.openWithRecovery();
    }

    connect(): Promise<void> {
        if (!this.running) {
            this.running = true;
            this.setStatus(this.hasConnected ? 'reconnecting' : 'connecting');
        }
        if (this.socket?.readyState === WEBSOCKET_OPEN) {
            return Promise.resolve();
        }
        if (this.openingPromise) {
            return this.openingPromise;
        }
        this.openingPromise = this.openSocket();
        const opening = this.openingPromise;
        void opening
            .finally(() => {
                if (this.openingPromise === opening) {
                    this.openingPromise = null;
                }
            })
            .catch(() => {
                // The original promise remains the caller's error surface.
            });
        return this.openingPromise;
    }

    stop(): void {
        this.running = false;
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        this.stopHeartbeat();
        this.reconnectAttempts = 0;
        const socket = this.socket;
        this.socket = null;
        if (socket) {
            socket.onopen = null;
            socket.onmessage = null;
            socket.onerror = null;
            socket.onclose = null;
            if (
                socket.readyState === WEBSOCKET_OPEN ||
                socket.readyState === WEBSOCKET_CONNECTING
            ) {
                socket.close();
            }
        }
        this.setStatus('idle');
    }

    send(message: PresenceSocketMessage): boolean {
        if (!this.socket || this.socket.readyState !== WEBSOCKET_OPEN) {
            return false;
        }
        this.socket.send(JSON.stringify(message));
        return true;
    }

    private async openWithRecovery(): Promise<void> {
        try {
            await this.connect();
        } catch {
            // The socket lifecycle schedules a retry and reports the original error.
        }
    }

    private async openSocket(): Promise<void> {
        if (!this.running) {
            return;
        }
        let socket: WebSocket | null = null;
        try {
            const ticket = await this.issueTicket();
            if (!this.running) {
                return;
            }

            const createdSocket = this.socketFactory(websocketUrl(ticket.ticket));
            socket = createdSocket;
            this.socket = createdSocket;
            await new Promise<void>((resolve, reject) => {
                let settled = false;
                createdSocket.onopen = () => {
                    settled = true;
                    this.hasConnected = true;
                    this.reconnectAttempts = 0;
                    this.setStatus('online');
                    this.startHeartbeat(createdSocket);
                    resolve();
                };
                createdSocket.onmessage = (event) => {
                    const message = parseSocketMessage(event.data);
                    if (message) {
                        this.onMessage?.(message);
                    }
                };
                createdSocket.onerror = () => {
                    if (!settled) {
                        settled = true;
                        reject(new Error('The presence socket could not connect.'));
                    }
                };
                createdSocket.onclose = () => {
                    if (!settled) {
                        settled = true;
                        reject(new Error('The presence socket closed before connecting.'));
                    }
                    this.handleSocketClosed(createdSocket);
                };
            });
        } catch (error) {
            if (socket && this.socket === socket) {
                this.socket = null;
            }
            this.stopHeartbeat();
            this.onError?.(error);
            if (this.running) {
                this.reconnectAttempts += 1;
                if (this.reconnectAttempts <= this.maxReconnectAttempts) {
                    this.setStatus('offline');
                    this.scheduleReconnect();
                } else {
                    this.setStatus('failed');
                }
            }
            throw error;
        }
    }

    private startHeartbeat(socket: WebSocket): void {
        this.stopHeartbeat();
        this.heartbeatTimer = setInterval(() => {
            if (this.socket === socket && socket.readyState === WEBSOCKET_OPEN) {
                socket.send(JSON.stringify({ type: 'heartbeat' }));
            }
        }, this.heartbeatIntervalMs);
    }

    private stopHeartbeat(): void {
        if (this.heartbeatTimer) {
            clearInterval(this.heartbeatTimer);
            this.heartbeatTimer = null;
        }
    }

    private handleSocketClosed(socket: WebSocket): void {
        if (this.socket !== socket) {
            return;
        }
        this.socket = null;
        this.stopHeartbeat();
        if (this.running) {
            this.setStatus('reconnecting');
            this.scheduleReconnect();
        }
    }

    private scheduleReconnect(): void {
        if (!this.running || this.reconnectTimer) {
            return;
        }
        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            void this.openWithRecovery();
        }, this.reconnectDelayMs);
    }

    private setStatus(status: PresenceClientStatus): void {
        if (status === this.currentStatus) {
            return;
        }
        this.currentStatus = status;
        this.onStatusChange?.(status);
    }
}
