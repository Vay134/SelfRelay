import { afterEach, describe, expect, it, vi } from 'vitest';

import { formatProbeLog, runAvailabilityProbe } from '../src/probe';
import { scheduled } from '../src/index';

const ENDPOINT = 'https://api.example.test/availability/probe';
const TOKEN = 'configured-token';

afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
});

describe('runAvailabilityProbe', () => {
    it('authenticates a successful backend probe and validates its safe response', async () => {
        const fetcher: typeof fetch = vi.fn(async (input, init) => {
            expect(String(input)).toBe(ENDPOINT);
            expect(init?.method).toBe('GET');
            expect(init?.headers).toEqual({
                Accept: 'application/json',
                Authorization: `Bearer ${TOKEN}`,
                'Cache-Control': 'no-store',
            });
            return new Response(JSON.stringify({ status: 'ok' }), {
                status: 200,
                headers: { 'content-type': 'application/json' },
            });
        });

        const result = await runAvailabilityProbe(
            { endpoint: ENDPOINT, token: TOKEN },
            {
                fetch: fetcher,
                now: vi.fn().mockReturnValueOnce(1000).mockReturnValueOnce(1123),
            },
        );

        expect(result).toEqual({
            status: 'ok',
            reason: null,
            httpStatus: 200,
            durationMs: 123,
        });
        expect(formatProbeLog(result)).not.toHaveProperty('token');
    });

    it('reports HTTP failures without copying response details', async () => {
        const fetcher: typeof fetch = vi.fn(
            async () => new Response('password=must-not-be-logged', { status: 503 }),
        );

        const result = await runAvailabilityProbe(
            { endpoint: ENDPOINT, token: TOKEN },
            { fetch: fetcher },
        );

        expect(result.status).toBe('failed');
        expect(result.reason).toBe('http_error');
        expect(result.httpStatus).toBe(503);
        expect(JSON.stringify(formatProbeLog(result))).not.toContain('password');
    });

    it('rejects missing and unsafe configuration before making a request', async () => {
        const fetcher: typeof fetch = vi.fn();

        await expect(
            runAvailabilityProbe({ endpoint: undefined, token: undefined }, { fetch: fetcher }),
        ).resolves.toMatchObject({
            status: 'failed',
            reason: 'configuration_missing',
        });
        await expect(
            runAvailabilityProbe(
                { endpoint: 'file:///safe/path', token: TOKEN },
                { fetch: fetcher },
            ),
        ).resolves.toMatchObject({ status: 'failed', reason: 'invalid_endpoint' });
        expect(fetcher).not.toHaveBeenCalled();
    });

    it('settles a hanging request as a bounded timeout', async () => {
        const fetcher: typeof fetch = vi.fn(
            (_input, init) =>
                new Promise<Response>((_resolve, reject) => {
                    init?.signal?.addEventListener('abort', () => {
                        reject(new DOMException('aborted', 'AbortError'));
                    });
                }),
        );

        const result = await runAvailabilityProbe(
            { endpoint: ENDPOINT, token: TOKEN, timeoutMs: 1 },
            { fetch: fetcher },
        );

        expect(result).toMatchObject({ status: 'failed', reason: 'timeout' });
    });
});

describe('scheduled worker handler', () => {
    it('logs an allowlisted structured result and waits for the probe', async () => {
        const fetcher: typeof fetch = vi.fn(
            async () => new Response(JSON.stringify({ status: 'ok' }), { status: 200 }),
        );
        vi.stubGlobal('fetch', fetcher);
        const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
        let waited: Promise<unknown> | undefined;

        await scheduled(
            { cron: '0 0 * * *', scheduledTime: 0 },
            { AVAILABILITY_PROBE_URL: ENDPOINT, AVAILABILITY_PROBE_TOKEN: TOKEN },
            {
                waitUntil: (promise) => {
                    waited = promise;
                },
            },
        );
        await waited;

        expect(fetcher).toHaveBeenCalledOnce();
        expect(log).toHaveBeenCalledOnce();
        const entry = JSON.parse(String(log.mock.calls[0]?.[0])) as Record<string, unknown>;
        expect(entry).toEqual(
            expect.objectContaining({
                component: 'availability-probe',
                event: 'probe.completed',
                status: 'ok',
            }),
        );
        expect(String(log.mock.calls[0]?.[0])).not.toContain(TOKEN);
    });
});
