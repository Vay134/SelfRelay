const configuredApiOrigin = (import.meta as ImportMeta & { env?: { VITE_API_ORIGIN?: string } }).env
    ?.VITE_API_ORIGIN;
export const API_ORIGIN = (configuredApiOrigin ?? 'http://localhost:8000').replace(/\/+$/u, '');
export const API_REQUEST_TIMEOUT_MS = 15_000;

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
    status: 'active' | 'inactive' | 'revoked' | string;
    created_at: string;
    last_seen_at: string;
    revoked_at: string | null;
    linked_by_device_id: string | null;
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

export async function getCurrentSession(): Promise<CurrentSession> {
    return apiRequest<CurrentSession>('/auth/session/current');
}
