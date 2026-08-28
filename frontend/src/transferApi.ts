import { API_ORIGIN, apiRequest } from './pairingApi';

export const TRANSFER_PROTOCOL_VERSION = 1;
export const SIGNALING_MESSAGE_TTL_MS = 30_000;

export type OnlineDevice = {
    device_id: string;
    label: string;
};

export type TransferStatus =
    | 'offered'
    | 'accepted'
    | 'negotiating'
    | 'connected'
    | 'transferring'
    | 'completed'
    | 'rejected'
    | 'expired'
    | 'cancelled'
    | 'failed';

export type TransferRequest = {
    v: number;
    transfer_id: string;
    sender_device_id: string;
    recipient_device_id: string;
    status: TransferStatus;
    created_at: string;
    expires_at: string;
};

export type TransferPeerDeviceKey = {
    device_id: string;
    public_key_spki: string;
};

export type WebSocketTicket = {
    ticket: string;
    ticket_id: string;
    expires_at: string;
};

export type TransferNotificationType =
    | 'transfer_offer'
    | 'transfer_accepted'
    | 'transfer_rejected'
    | 'transfer_cancelled'
    | 'transfer_expired';

export type TransferNotification = Omit<TransferRequest, 'status'> & {
    type: TransferNotificationType;
};

export type PresenceEvent = {
    type: 'presence';
    devices: OnlineDevice[];
};

export type HeartbeatEvent = {
    type: 'heartbeat' | 'pong';
};

export type SdpOfferEnvelope = {
    type: 'sdp_offer';
    v: 1;
    transfer_id: string;
    sender_device_id: string;
    recipient_device_id: string;
    expires_at: number;
    sdp: string;
};

export type SdpAnswerEnvelope = {
    type: 'sdp_answer';
    v: 1;
    transfer_id: string;
    sender_device_id: string;
    recipient_device_id: string;
    expires_at: number;
    sdp: string;
};

export type IceCandidateEnvelope = {
    type: 'ice_candidate';
    v: 1;
    transfer_id: string;
    sender_device_id: string;
    recipient_device_id: string;
    expires_at: number;
    candidate: string;
    sdp_mid?: string;
    sdp_mline_index?: number;
    username_fragment?: string;
};

export type SignalingEnvelope = SdpOfferEnvelope | SdpAnswerEnvelope | IceCandidateEnvelope;

export type PresenceSocketMessage =
    | PresenceEvent
    | HeartbeatEvent
    | TransferNotification
    | SignalingEnvelope;

export type IceCandidateInput = {
    candidate: string;
    sdpMid?: string | null;
    sdpMLineIndex?: number | null;
    usernameFragment?: string | null;
};

function actionResponse(body: unknown): TransferRequest {
    const candidate =
        typeof body === 'object' && body !== null && 'transfer' in body
            ? (body as { transfer?: unknown }).transfer
            : body;
    if (typeof candidate !== 'object' || candidate === null) {
        throw new TypeError('The transfer response is invalid.');
    }
    return candidate as TransferRequest;
}

export async function issueWebSocketTicket(): Promise<WebSocketTicket> {
    return apiRequest<WebSocketTicket>('/auth/websocket/ticket', { method: 'POST' });
}

export async function listOnlineDevices(): Promise<OnlineDevice[]> {
    const body = await apiRequest<{ devices?: OnlineDevice[] }>('/auth/devices/online');
    return Array.isArray(body.devices) ? body.devices : [];
}

export async function listTransfers(): Promise<TransferRequest[]> {
    const body = await apiRequest<{ transfers?: TransferRequest[] }>('/auth/transfers');
    return Array.isArray(body.transfers) ? body.transfers : [];
}

export async function createTransferOffer(recipientDeviceId: string): Promise<TransferRequest> {
    const body = await apiRequest<unknown>('/auth/transfers', {
        method: 'POST',
        body: JSON.stringify({
            recipient_device_id: recipientDeviceId,
            protocol_version: TRANSFER_PROTOCOL_VERSION,
            v: TRANSFER_PROTOCOL_VERSION,
        }),
    });
    return actionResponse(body);
}

async function transferAction(transferId: string, action: 'accept' | 'reject' | 'cancel') {
    const body = await apiRequest<unknown>(
        `/auth/transfers/${encodeURIComponent(transferId)}/${action}`,
        { method: 'POST' },
    );
    return actionResponse(body);
}

export function acceptTransfer(transferId: string): Promise<TransferRequest> {
    return transferAction(transferId, 'accept');
}

export function rejectTransfer(transferId: string): Promise<TransferRequest> {
    return transferAction(transferId, 'reject');
}

export function cancelTransfer(transferId: string): Promise<TransferRequest> {
    return transferAction(transferId, 'cancel');
}

export function getTransferPeerDeviceKey(transferId: string): Promise<TransferPeerDeviceKey> {
    return apiRequest<TransferPeerDeviceKey>(
        `/auth/transfers/${encodeURIComponent(transferId)}/peer-key`,
    );
}

export function websocketUrl(ticket: string): string {
    const url = new URL(API_ORIGIN);
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    url.pathname = '/auth/ws';
    url.search = `?ticket=${encodeURIComponent(ticket)}`;
    return url.toString();
}

export function signalingExpiry(
    transferExpiresAt: string,
    now = Date.now(),
    ttlMs = SIGNALING_MESSAGE_TTL_MS,
): number {
    const transferExpiry = new Date(transferExpiresAt).getTime();
    const proposedExpiry = now + ttlMs;
    return Number.isFinite(transferExpiry)
        ? Math.min(proposedExpiry, transferExpiry)
        : proposedExpiry;
}

function envelopeFields(transfer: TransferRequest, now: number) {
    return {
        v: TRANSFER_PROTOCOL_VERSION as 1,
        transfer_id: transfer.transfer_id,
        sender_device_id: transfer.sender_device_id,
        recipient_device_id: transfer.recipient_device_id,
        expires_at: signalingExpiry(transfer.expires_at, now),
    };
}

export function buildSdpOfferEnvelope(
    transfer: TransferRequest,
    sdp: string,
    now = Date.now(),
): SdpOfferEnvelope {
    return {
        type: 'sdp_offer',
        ...envelopeFields(transfer, now),
        sdp,
    };
}

export function buildSdpAnswerEnvelope(
    transfer: TransferRequest,
    sdp: string,
    now = Date.now(),
): SdpAnswerEnvelope {
    return {
        type: 'sdp_answer',
        ...envelopeFields(transfer, now),
        sdp,
    };
}

export function buildIceCandidateEnvelope(
    transfer: TransferRequest,
    candidate: IceCandidateInput,
    now = Date.now(),
): IceCandidateEnvelope {
    const envelope: IceCandidateEnvelope = {
        type: 'ice_candidate',
        ...envelopeFields(transfer, now),
        candidate: candidate.candidate,
    };
    if (candidate.sdpMid !== undefined && candidate.sdpMid !== null) {
        envelope.sdp_mid = candidate.sdpMid;
    }
    if (candidate.sdpMLineIndex !== undefined && candidate.sdpMLineIndex !== null) {
        envelope.sdp_mline_index = candidate.sdpMLineIndex;
    }
    if (candidate.usernameFragment !== undefined && candidate.usernameFragment !== null) {
        envelope.username_fragment = candidate.usernameFragment;
    }
    return envelope;
}

export function parseSocketMessage(raw: unknown): PresenceSocketMessage | null {
    let value: unknown = raw;
    if (typeof raw === 'string') {
        try {
            value = JSON.parse(raw) as unknown;
        } catch {
            return null;
        }
    }
    if (typeof value !== 'object' || value === null || !('type' in value)) {
        return null;
    }
    const messageType = (value as { type?: unknown }).type;
    if (typeof messageType !== 'string') {
        return null;
    }
    if (
        messageType === 'presence' ||
        messageType === 'heartbeat' ||
        messageType === 'pong' ||
        messageType === 'transfer_offer' ||
        messageType === 'transfer_accepted' ||
        messageType === 'transfer_rejected' ||
        messageType === 'transfer_cancelled' ||
        messageType === 'transfer_expired' ||
        messageType === 'sdp_offer' ||
        messageType === 'sdp_answer' ||
        messageType === 'ice_candidate'
    ) {
        return value as PresenceSocketMessage;
    }
    return null;
}
