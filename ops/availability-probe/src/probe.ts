export const DEFAULT_PROBE_TIMEOUT_MS = 10_000;
export const MAX_PROBE_TIMEOUT_MS = 30_000;

export type ProbeFailureReason =
    | 'configuration_missing'
    | 'invalid_endpoint'
    | 'timeout'
    | 'network_error'
    | 'http_error'
    | 'invalid_response';

export interface ProbeResult {
    status: 'ok' | 'failed';
    reason: ProbeFailureReason | null;
    httpStatus: number | null;
    durationMs: number;
}

export interface ProbeConfig {
    endpoint: string | undefined;
    token: string | undefined;
    timeoutMs?: number;
}

export interface ProbeDependencies {
    fetch: typeof fetch;
    now?: () => number;
    setTimeout?: typeof globalThis.setTimeout;
    clearTimeout?: typeof globalThis.clearTimeout;
}

const SAFE_SUCCESS_STATUS = 'ok';

function boundedTimeout(timeoutMs: number | undefined): number {
    if (!Number.isFinite(timeoutMs) || timeoutMs === undefined || timeoutMs <= 0) {
        return DEFAULT_PROBE_TIMEOUT_MS;
    }

    return Math.min(Math.max(Math.round(timeoutMs), 1), MAX_PROBE_TIMEOUT_MS);
}

function elapsedMilliseconds(startedAt: number, now: () => number): number {
    const elapsed = now() - startedAt;
    return Number.isFinite(elapsed) ? Math.max(0, Math.round(elapsed)) : 0;
}

function failure(
    reason: ProbeFailureReason,
    startedAt: number,
    now: () => number,
    httpStatus: number | null = null,
): ProbeResult {
    return {
        status: 'failed',
        reason,
        httpStatus,
        durationMs: elapsedMilliseconds(startedAt, now),
    };
}

function success(startedAt: number, now: () => number, httpStatus: number): ProbeResult {
    return {
        status: 'ok',
        reason: null,
        httpStatus,
        durationMs: elapsedMilliseconds(startedAt, now),
    };
}

function parseEndpoint(endpoint: string | undefined): URL | null {
    const value = endpoint?.trim();
    if (!value) {
        return null;
    }

    try {
        const parsed = new URL(value);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
            return null;
        }
        if (parsed.username || parsed.password) {
            return null;
        }
        return parsed;
    } catch {
        return null;
    }
}

function responseIsSuccessful(body: unknown): boolean {
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
        return false;
    }

    return 'status' in body && body.status === SAFE_SUCCESS_STATUS;
}

/**
 * Run one authenticated, database-backed availability check.
 *
 * The backend owns the database operation. This function intentionally does
 * not retry: the low-frequency scheduler should create one bounded request,
 * and a failed run should remain visible to the operator.
 */
export async function runAvailabilityProbe(
    config: ProbeConfig,
    dependencies: ProbeDependencies = { fetch },
): Promise<ProbeResult> {
    const now = dependencies.now ?? Date.now;
    const startedAt = now();
    const endpoint = parseEndpoint(config.endpoint);
    const token = config.token?.trim();

    if (!config.endpoint?.trim() || !token) {
        return failure('configuration_missing', startedAt, now);
    }

    if (!endpoint) {
        return failure('invalid_endpoint', startedAt, now);
    }

    const timeoutMs = boundedTimeout(config.timeoutMs);
    const controller = new AbortController();
    const setTimer = dependencies.setTimeout ?? globalThis.setTimeout;
    const clearTimer = dependencies.clearTimeout ?? globalThis.clearTimeout;
    let timedOut = false;
    const timeout = setTimer(() => {
        timedOut = true;
        controller.abort();
    }, timeoutMs);

    try {
        const response = await dependencies.fetch(endpoint, {
            method: 'GET',
            headers: {
                Accept: 'application/json',
                Authorization: `Bearer ${token}`,
                'Cache-Control': 'no-store',
            },
            signal: controller.signal,
        });

        if (!response.ok) {
            return failure('http_error', startedAt, now, response.status);
        }

        let body: unknown;
        try {
            body = await response.json();
        } catch {
            return failure('invalid_response', startedAt, now, response.status);
        }

        return responseIsSuccessful(body)
            ? success(startedAt, now, response.status)
            : failure('invalid_response', startedAt, now, response.status);
    } catch {
        return failure(timedOut ? 'timeout' : 'network_error', startedAt, now);
    } finally {
        clearTimer(timeout);
    }
}

/**
 * Return the only fields permitted in a scheduler log entry.
 *
 * No URL, authorization value, response body, or exception text is included.
 */
export function formatProbeLog(result: ProbeResult): Record<string, unknown> {
    return {
        component: 'availability-probe',
        event: 'probe.completed',
        status: result.status,
        reason: result.reason,
        http_status: result.httpStatus,
        duration_ms: result.durationMs,
    };
}
