import { API_ORIGIN } from '../pairingApi';

export type AvailabilityState = 'starting' | 'ready' | 'degraded' | 'failed';

export type AvailabilitySnapshot = {
    state: AvailabilityState;
    attempt: number;
    maxAttempts: number;
};

export type AvailabilityFetcher = (
    input: RequestInfo | URL,
    init?: RequestInit,
) => Promise<Response>;

export type AvailabilityControllerOptions = {
    fetcher?: AvailabilityFetcher;
    origin?: string;
    maxAttempts?: number;
    requestTimeoutMs?: number;
    retryBaseDelayMs?: number;
    retryMaxDelayMs?: number;
    jitterRatio?: number;
    random?: () => number;
    timer?: (callback: () => void, delayMs: number) => ReturnType<typeof setTimeout>;
    clearTimer?: (timer: ReturnType<typeof setTimeout>) => void;
    onStateChange?: (state: AvailabilityState, snapshot: AvailabilitySnapshot) => void;
};

export const AVAILABILITY_WAKE_PATH = '/availability/wake';
export const AVAILABILITY_READINESS_PATH = '/availability/readiness';
export const DEFAULT_AVAILABILITY_MAX_ATTEMPTS = 4;
export const DEFAULT_AVAILABILITY_REQUEST_TIMEOUT_MS = 5_000;
export const DEFAULT_AVAILABILITY_RETRY_BASE_DELAY_MS = 250;
export const DEFAULT_AVAILABILITY_RETRY_MAX_DELAY_MS = 5_000;
export const DEFAULT_AVAILABILITY_JITTER_RATIO = 0.25;

const SAFE_FAILURE_MESSAGE = 'The secure transfer service is temporarily unavailable.';

class AvailabilityRequestError extends Error {
    constructor() {
        super('Availability request failed.');
        this.name = 'AvailabilityRequestError';
    }
}

class AvailabilityAbortedError extends Error {
    constructor() {
        super('Availability request was cancelled.');
        this.name = 'AvailabilityAbortedError';
    }
}

export class AvailabilityError extends Error {
    readonly attempts: number;

    constructor(attempts: number) {
        super(SAFE_FAILURE_MESSAGE);
        this.name = 'AvailabilityError';
        this.attempts = attempts;
    }
}

export type RetryDelayOptions = {
    baseDelayMs?: number;
    maxDelayMs?: number;
    jitterRatio?: number;
    random?: () => number;
};

function positiveNumber(value: number, name: string): number {
    if (!Number.isFinite(value) || value <= 0) {
        throw new TypeError(`${name} must be positive.`);
    }
    return value;
}

function positiveInteger(value: number, name: string): number {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${name} must be a positive integer.`);
    }
    return value;
}

function boundedJitterRatio(value: number): number {
    if (!Number.isFinite(value) || value < 0 || value > 1) {
        throw new TypeError('The jitter ratio must be between zero and one.');
    }
    return value;
}

export function availabilityRetryDelay(
    attempt: number,
    {
        baseDelayMs = DEFAULT_AVAILABILITY_RETRY_BASE_DELAY_MS,
        maxDelayMs = DEFAULT_AVAILABILITY_RETRY_MAX_DELAY_MS,
        jitterRatio = DEFAULT_AVAILABILITY_JITTER_RATIO,
        random = Math.random,
    }: RetryDelayOptions = {},
): number {
    positiveNumber(baseDelayMs, 'The retry base delay');
    positiveNumber(maxDelayMs, 'The retry maximum delay');
    boundedJitterRatio(jitterRatio);
    if (!Number.isSafeInteger(attempt) || attempt <= 0) {
        throw new TypeError('The retry attempt must be a positive integer.');
    }

    const exponentialDelay = Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1));
    const sample = Math.min(1, Math.max(0, random()));
    const jitter = exponentialDelay * jitterRatio * (sample * 2 - 1);
    return Math.min(maxDelayMs, Math.max(0, exponentialDelay + jitter));
}

function defaultTimer(callback: () => void, delayMs: number): ReturnType<typeof setTimeout> {
    return setTimeout(callback, delayMs);
}

function defaultClearTimer(timer: ReturnType<typeof setTimeout>): void {
    clearTimeout(timer);
}

function defaultFetcher(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    return fetch(input, init);
}

export class AvailabilityController {
    private readonly fetcher: AvailabilityFetcher;
    private readonly origin: string;
    private readonly maxAttempts: number;
    private readonly requestTimeoutMs: number;
    private readonly retryBaseDelayMs: number;
    private readonly retryMaxDelayMs: number;
    private readonly jitterRatio: number;
    private readonly random: () => number;
    private readonly timer: (
        callback: () => void,
        delayMs: number,
    ) => ReturnType<typeof setTimeout>;
    private readonly clearTimer: (timer: ReturnType<typeof setTimeout>) => void;
    private readonly onStateChange?: (
        state: AvailabilityState,
        snapshot: AvailabilitySnapshot,
    ) => void;
    private currentState: AvailabilityState = 'starting';
    private currentAttempt = 0;
    private runPromise: Promise<void> | null = null;
    private abortController: AbortController | null = null;

    constructor(options: AvailabilityControllerOptions = {}) {
        this.fetcher = options.fetcher ?? defaultFetcher;
        this.origin = (options.origin ?? API_ORIGIN).replace(/\/+$/u, '');
        this.maxAttempts = positiveInteger(
            options.maxAttempts ?? DEFAULT_AVAILABILITY_MAX_ATTEMPTS,
            'The maximum availability attempts',
        );
        this.requestTimeoutMs = positiveNumber(
            options.requestTimeoutMs ?? DEFAULT_AVAILABILITY_REQUEST_TIMEOUT_MS,
            'The availability request timeout',
        );
        this.retryBaseDelayMs = positiveNumber(
            options.retryBaseDelayMs ?? DEFAULT_AVAILABILITY_RETRY_BASE_DELAY_MS,
            'The retry base delay',
        );
        this.retryMaxDelayMs = positiveNumber(
            options.retryMaxDelayMs ?? DEFAULT_AVAILABILITY_RETRY_MAX_DELAY_MS,
            'The retry maximum delay',
        );
        if (this.retryMaxDelayMs < this.retryBaseDelayMs) {
            throw new TypeError('The retry maximum delay must not be below the base delay.');
        }
        this.jitterRatio = boundedJitterRatio(
            options.jitterRatio ?? DEFAULT_AVAILABILITY_JITTER_RATIO,
        );
        this.random = options.random ?? Math.random;
        this.timer = options.timer ?? defaultTimer;
        this.clearTimer = options.clearTimer ?? defaultClearTimer;
        this.onStateChange = options.onStateChange;
    }

    get state(): AvailabilityState {
        return this.currentState;
    }

    get status(): AvailabilityState {
        return this.currentState;
    }

    get attempt(): number {
        return this.currentAttempt;
    }

    get snapshot(): AvailabilitySnapshot {
        return {
            state: this.currentState,
            attempt: this.currentAttempt,
            maxAttempts: this.maxAttempts,
        };
    }

    start(): Promise<void> {
        if (this.currentState === 'ready') {
            return Promise.resolve();
        }
        if (this.runPromise) {
            return this.runPromise;
        }
        if (this.currentState === 'failed') {
            return Promise.reject(new AvailabilityError(this.currentAttempt));
        }

        const controller = new AbortController();
        this.abortController = controller;
        const run = this.run(controller.signal);
        this.runPromise = run;
        void run
            .finally(() => {
                if (this.runPromise === run) {
                    this.runPromise = null;
                    this.abortController = null;
                }
            })
            .catch(() => {
                // The original promise remains the caller's error surface.
            });
        return run;
    }

    dispose(): void {
        this.abortController?.abort();
        this.abortController = null;
        this.runPromise = null;
    }

    private async run(signal: AbortSignal): Promise<void> {
        for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
            this.currentAttempt = attempt;
            this.setState(attempt === 1 ? 'starting' : 'degraded');
            try {
                await this.check(signal);
                this.setState('ready');
                return;
            } catch (error) {
                if (signal.aborted || error instanceof AvailabilityAbortedError) {
                    return;
                }
                if (attempt === this.maxAttempts) {
                    this.setState('failed');
                    throw new AvailabilityError(attempt);
                }
                this.setState('degraded');
                await this.wait(
                    availabilityRetryDelay(attempt, {
                        baseDelayMs: this.retryBaseDelayMs,
                        maxDelayMs: this.retryMaxDelayMs,
                        jitterRatio: this.jitterRatio,
                        random: this.random,
                    }),
                    signal,
                );
            }
        }
    }

    private async check(signal: AbortSignal): Promise<void> {
        await this.requestStatus(AVAILABILITY_WAKE_PATH, 'ok', signal);
        await this.requestStatus(AVAILABILITY_READINESS_PATH, 'ready', signal);
    }

    private async requestStatus(
        path: string,
        expectedStatus: string,
        signal: AbortSignal,
    ): Promise<void> {
        const requestController = new AbortController();
        const abortRequest = () => requestController.abort();
        const operation = (async () => {
            const response = await this.fetcher(`${this.origin}${path}`, {
                credentials: 'include',
                headers: { Accept: 'application/json' },
                signal: requestController.signal,
            });
            if (!response.ok) {
                throw new AvailabilityRequestError();
            }
            let body: unknown;
            try {
                body = await response.json();
            } catch {
                throw new AvailabilityRequestError();
            }
            if (
                typeof body !== 'object' ||
                body === null ||
                (body as { status?: unknown }).status !== expectedStatus
            ) {
                throw new AvailabilityRequestError();
            }
        })();
        const timeout = new Promise<never>((_, reject) => {
            const timeoutId = this.timer(() => {
                requestController.abort();
                reject(new AvailabilityRequestError());
            }, this.requestTimeoutMs);
            void operation
                .finally(() => this.clearTimer(timeoutId))
                .catch(() => {
                    // The operation's rejection is observed by Promise.race below.
                });
        });
        let handleAbort: (() => void) | null = null;
        const cancelled = new Promise<never>((_, reject) => {
            if (signal.aborted) {
                reject(new AvailabilityAbortedError());
                return;
            }
            handleAbort = () => {
                abortRequest();
                reject(new AvailabilityAbortedError());
            };
            signal.addEventListener('abort', handleAbort, { once: true });
        });
        try {
            await Promise.race([operation, timeout, cancelled]);
        } finally {
            if (handleAbort) {
                signal.removeEventListener('abort', handleAbort);
            }
            requestController.abort();
        }
    }

    private wait(delayMs: number, signal: AbortSignal): Promise<void> {
        return new Promise((resolve) => {
            if (signal.aborted) {
                resolve();
                return;
            }
            const timer = this.timer(() => {
                signal.removeEventListener('abort', abort);
                resolve();
            }, delayMs);
            const abort = () => {
                this.clearTimer(timer);
                signal.removeEventListener('abort', abort);
                resolve();
            };
            signal.addEventListener('abort', abort, { once: true });
        });
    }

    private setState(state: AvailabilityState): void {
        this.currentState = state;
        this.onStateChange?.(state, this.snapshot);
    }
}
