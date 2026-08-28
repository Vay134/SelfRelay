import {
    PAIRING_APPROVAL_VERSION,
    encodeBase64Url,
    signPairingApproval,
    signPairingEnrollment,
} from './deviceIdentity';

const configuredApiOrigin = (import.meta as ImportMeta & { env?: { VITE_API_ORIGIN?: string } }).env
    ?.VITE_API_ORIGIN;
export const API_ORIGIN = (configuredApiOrigin ?? 'http://localhost:8000').replace(/\/+$/u, '');
export const PAIRING_PROTOCOL_VERSION = 1;
export const API_REQUEST_TIMEOUT_MS = 15_000;

export type PairingStatus = 'pending' | 'approved' | 'rejected' | 'consumed' | 'expired';

export type PairingRequestMetadata = {
    request_id: string;
    status: PairingStatus;
    requested_label: string;
    requested_fingerprint: string;
    request_nonce: string;
    created_at: string;
    expires_at: string;
    approval_nonce?: string;
};

export type PairingRequestStart = {
    message: string;
    request_id: string;
    status: 'pending';
    fingerprint: string;
    request_nonce: string;
    comparison_code: string;
    created_at: string;
    expires_at: string;
};

export type PairingRequestStatus = PairingRequestMetadata & {
    account_id?: string;
    payload?: Record<string, unknown>;
};

export type PairingApprovalRequest = PairingRequestMetadata & {
    account_id: string;
    account_device_epoch: number;
};

export type CurrentSession = {
    authenticated: true;
    account_id: string;
    account_device_epoch: number;
    csrf_token: string;
    session_id: string;
    device_id: string;
};

export type AuthenticatedDevice = {
    device_id: string;
    epoch: number;
    label: string;
    fingerprint: string;
    status: 'active' | 'revoked' | string;
    created_at: string;
    last_seen_at: string;
    revoked_at: string | null;
    approved_by_device_id: string | null;
};

export type PairingEnrollmentResult = {
    authenticated: true;
    account_id: string;
    device: AuthenticatedDevice;
    csrf_token: string;
    session: Record<string, unknown>;
    recovery: boolean;
    warning: string | null;
};

export class ApiError extends Error {
    readonly status: number;
    readonly detail: string;

    constructor(status: number, detail: string) {
        super(detail);
        this.name = 'ApiError';
        this.status = status;
        this.detail = detail;
    }
}

let csrfToken: string | null = null;

export function currentCsrfToken(): string | null {
    return csrfToken;
}

export function clearApiSession(): void {
    csrfToken = null;
}

function rememberCsrf(body: unknown): void {
    if (typeof body === 'object' && body !== null && 'csrf_token' in body) {
        const token = (body as { csrf_token?: unknown }).csrf_token;
        if (typeof token === 'string' && token.length > 0) {
            csrfToken = token;
        }
    }
}

async function responseBody(response: Response): Promise<unknown> {
    const text = await response.text();
    if (!text) {
        return null;
    }
    try {
        return JSON.parse(text) as unknown;
    } catch {
        return { detail: text };
    }
}

function errorDetail(body: unknown, fallback: string): string {
    if (typeof body === 'object' && body !== null && 'detail' in body) {
        const detail = (body as { detail?: unknown }).detail;
        if (typeof detail === 'string' && detail.length > 0) {
            return detail;
        }
    }
    return fallback;
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set('Accept', 'application/json');
    if (init.body !== undefined && init.body !== null && !headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
    }
    if (csrfToken && init.method && !['GET', 'HEAD', 'OPTIONS'].includes(init.method)) {
        headers.set('X-CSRF-Token', csrfToken);
    }

    let response: Response;
    const timeoutController = init.signal ? null : new AbortController();
    const timeout = timeoutController
        ? setTimeout(() => timeoutController.abort(), API_REQUEST_TIMEOUT_MS)
        : null;
    try {
        response = await fetch(`${API_ORIGIN}${path}`, {
            ...init,
            credentials: 'include',
            headers,
            ...(timeoutController ? { signal: timeoutController.signal } : {}),
        });
    } catch (error) {
        if (timeoutController?.signal.aborted) {
            throw new ApiError(0, 'The secure transfer service did not respond in time.');
        }
        throw new ApiError(
            0,
            error instanceof Error ? error.message : 'The secure transfer service is unreachable.',
        );
    } finally {
        if (timeout !== null) {
            clearTimeout(timeout);
        }
    }

    const body = await responseBody(response);
    rememberCsrf(body);
    if (!response.ok) {
        if (response.status === 403) {
            csrfToken = null;
        }
        throw new ApiError(
            response.status,
            errorDetail(body, `Request failed (${response.status}).`),
        );
    }
    return body as T;
}

function jsonBody(value: unknown): string {
    return JSON.stringify(value);
}

export async function startPairingRequest(
    email: string,
    publicKeySpki: Uint8Array,
    fingerprint: string,
    label: string,
): Promise<PairingRequestStart> {
    return apiRequest<PairingRequestStart>('/auth/pairing/requests', {
        method: 'POST',
        body: jsonBody({
            email,
            public_key_spki: encodeBase64Url(publicKeySpki),
            fingerprint,
            label,
        }),
    });
}

export async function getPairingRequestStatus(requestId: string): Promise<PairingRequestStatus> {
    return apiRequest<PairingRequestStatus>(
        `/auth/pairing/requests/${encodeURIComponent(requestId)}`,
    );
}

export async function getCurrentSession(): Promise<CurrentSession> {
    return apiRequest<CurrentSession>('/auth/session/current');
}

export async function listPendingPairingRequests(): Promise<PairingApprovalRequest[]> {
    const body = await apiRequest<{ requests: PairingApprovalRequest[] }>('/auth/pairing/requests');
    return Array.isArray(body.requests) ? body.requests : [];
}

export function normalizeProtocolTimestamp(value: string): string {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError('A timestamp is required.');
    }
    const utcValue = value.endsWith('Z')
        ? value.slice(0, -1)
        : value.endsWith('+00:00')
          ? value.slice(0, -6)
          : null;
    if (utcValue === null) {
        throw new TypeError('Pairing timestamps must be UTC.');
    }
    const [whole, fraction = ''] = utcValue.split('.');
    if (!whole || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/u.test(whole)) {
        throw new TypeError('Pairing timestamp has an invalid format.');
    }
    if (fraction && !/^\d+$/u.test(fraction)) {
        throw new TypeError('Pairing timestamp has an invalid fraction.');
    }
    return `${whole}.${fraction.padEnd(6, '0').slice(0, 6)}Z`;
}

export function buildPairingApprovalPayload(
    request: PairingApprovalRequest,
    approvalNonce: string,
): Record<string, unknown> {
    return {
        account_device_epoch: request.account_device_epoch,
        account_id: request.account_id,
        approval_nonce: approvalNonce,
        expires_at: normalizeProtocolTimestamp(request.expires_at),
        pairing_approval_version: PAIRING_APPROVAL_VERSION,
        pairing_request_id: request.request_id,
        protocol_version: PAIRING_PROTOCOL_VERSION,
        requested_fingerprint: request.requested_fingerprint,
        request_nonce: request.request_nonce,
    };
}

export async function approvePairingRequest(
    pairingRequest: PairingApprovalRequest,
    comparisonCode: string,
    approvalNonce: Uint8Array,
    approvingIdentity: Parameters<typeof signPairingApproval>[0],
): Promise<PairingRequestMetadata> {
    const encodedNonce = encodeBase64Url(approvalNonce);
    const payload = buildPairingApprovalPayload(pairingRequest, encodedNonce);
    const signature = await signPairingApproval(approvingIdentity, payload);
    const body = await apiRequest<{ request: PairingRequestMetadata }>(
        `/auth/pairing/requests/${encodeURIComponent(pairingRequest.request_id)}/approve`,
        {
            method: 'POST',
            body: jsonBody({
                comparison_code: comparisonCode,
                approval_nonce: encodedNonce,
                signature,
            }),
        },
    );
    return body.request;
}

export async function rejectPairingRequest(requestId: string): Promise<PairingRequestMetadata> {
    const body = await apiRequest<{ request: PairingRequestMetadata }>(
        `/auth/pairing/requests/${encodeURIComponent(requestId)}/reject`,
        { method: 'POST' },
    );
    return body.request;
}

export async function completePairingRequest(
    pairingRequest: PairingRequestStatus,
    publicKeySpki: Uint8Array,
    fingerprint: string,
    requestedIdentity: Parameters<typeof signPairingEnrollment>[0],
): Promise<PairingEnrollmentResult> {
    if (!pairingRequest.account_id || !pairingRequest.payload || !pairingRequest.approval_nonce) {
        throw new ApiError(0, 'The approved pairing is missing its proof payload.');
    }
    const signature = await signPairingEnrollment(requestedIdentity, pairingRequest.payload);
    return apiRequest<PairingEnrollmentResult>(
        `/auth/pairing/requests/${encodeURIComponent(pairingRequest.request_id)}/complete`,
        {
            method: 'POST',
            body: jsonBody({
                account_id: pairingRequest.account_id,
                public_key_spki: encodeBase64Url(publicKeySpki),
                fingerprint,
                request_nonce: pairingRequest.request_nonce,
                approval_nonce: pairingRequest.approval_nonce,
                signature,
            }),
        },
    );
}
