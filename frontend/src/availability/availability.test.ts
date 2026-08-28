import { afterEach, describe, expect, it, vi } from 'vitest';

import {
    AvailabilityController,
    AvailabilityError,
    type AvailabilityFetcher,
    availabilityRetryDelay,
} from './availability';

function jsonResponse(status: string, statusCode = 200): Response {
    return new Response(JSON.stringify({ status }), {
        status: statusCode,
        headers: { 'Content-Type': 'application/json' },
    });
}

async function flushMicrotasks(): Promise<void> {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
}

afterEach(() => {
    vi.useRealTimers();
});

describe('availabilityRetryDelay', () => {
    it('keeps exponential delays within the configured jitter and cap bounds', () => {
        expect(
            availabilityRetryDelay(1, {
                baseDelayMs: 100,
                maxDelayMs: 500,
                jitterRatio: 0.25,
                random: () => 0,
            }),
        ).toBe(75);
        expect(
            availabilityRetryDelay(2, {
                baseDelayMs: 100,
                maxDelayMs: 500,
                jitterRatio: 0.25,
                random: () => 1,
            }),
        ).toBe(250);
        expect(
            availabilityRetryDelay(4, {
                baseDelayMs: 100,
                maxDelayMs: 500,
                jitterRatio: 0.25,
                random: () => 1,
            }),
        ).toBe(500);
    });
});

describe('AvailabilityController', () => {
    it('wakes the backend before checking readiness and reaches ready', async () => {
        const paths: string[] = [];
        const states: string[] = [];
        const fetcher: AvailabilityFetcher = vi.fn(async (input) => {
            const path = new URL(String(input)).pathname;
            paths.push(path);
            return jsonResponse(path.endsWith('/wake') ? 'ok' : 'ready');
        });
        const controller = new AvailabilityController({
            origin: 'https://api.example.test',
            fetcher,
            onStateChange: (state) => states.push(state),
        });

        await controller.start();

        expect(paths).toEqual(['/availability/wake', '/availability/readiness']);
        expect(states).toEqual(['starting', 'ready']);
        expect(controller.snapshot).toEqual({ state: 'ready', attempt: 1, maxAttempts: 4 });
    });

    it('caps failed retries and reports only a safe terminal error', async () => {
        vi.useFakeTimers();
        const states: Array<{ state: string; attempt: number }> = [];
        const fetcher: AvailabilityFetcher = vi.fn(async () => {
            throw new Error('database password must not escape');
        });
        const controller = new AvailabilityController({
            fetcher,
            maxAttempts: 4,
            retryBaseDelayMs: 100,
            retryMaxDelayMs: 500,
            jitterRatio: 0.25,
            random: () => 1,
            onStateChange: (state, snapshot) => states.push({ state, attempt: snapshot.attempt }),
        });
        const started = controller.start();

        await flushMicrotasks();
        expect(fetcher).toHaveBeenCalledTimes(1);
        await vi.advanceTimersByTimeAsync(125);
        await flushMicrotasks();
        expect(fetcher).toHaveBeenCalledTimes(2);
        await vi.advanceTimersByTimeAsync(250);
        await flushMicrotasks();
        expect(fetcher).toHaveBeenCalledTimes(3);
        await vi.advanceTimersByTimeAsync(500);
        await flushMicrotasks();

        await expect(started).rejects.toMatchObject({
            name: 'AvailabilityError',
            attempts: 4,
            message: 'The secure transfer service is temporarily unavailable.',
        });
        expect(fetcher).toHaveBeenCalledTimes(4);
        expect(states).toEqual([
            { state: 'starting', attempt: 1 },
            { state: 'degraded', attempt: 1 },
            { state: 'degraded', attempt: 2 },
            { state: 'degraded', attempt: 2 },
            { state: 'degraded', attempt: 3 },
            { state: 'degraded', attempt: 3 },
            { state: 'degraded', attempt: 4 },
            { state: 'failed', attempt: 4 },
        ]);
    });

    it('bounds an unresponsive HTTP request and never opens a second loop', async () => {
        vi.useFakeTimers();
        const fetcher: AvailabilityFetcher = vi.fn(
            (_input, init) =>
                new Promise<Response>((_, reject) => {
                    init?.signal?.addEventListener(
                        'abort',
                        () => reject(new Error('request aborted')),
                        { once: true },
                    );
                }),
        );
        const controller = new AvailabilityController({
            fetcher,
            maxAttempts: 1,
            requestTimeoutMs: 100,
        });
        const started = controller.start();

        await vi.advanceTimersByTimeAsync(100);

        await expect(started).rejects.toBeInstanceOf(AvailabilityError);
        expect(controller.state).toBe('failed');
        expect(fetcher).toHaveBeenCalledTimes(1);
    });

    it('does not duplicate concurrent starts', async () => {
        const fetcher: AvailabilityFetcher = vi.fn(async (input) => {
            const path = new URL(String(input)).pathname;
            return jsonResponse(path.endsWith('/wake') ? 'ok' : 'ready');
        });
        const controller = new AvailabilityController({ fetcher });

        const first = controller.start();
        const second = controller.start();
        await Promise.all([first, second]);

        expect(first).toBe(second);
        expect(fetcher).toHaveBeenCalledTimes(2);
    });
});
