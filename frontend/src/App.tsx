import { type FormEvent, useCallback, useEffect, useState } from 'react';

import {
    ApiError,
    approvePairingRequest,
    completePairingRequest,
    getCurrentSession,
    getPairingRequestStatus,
    listPendingPairingRequests,
    rejectPairingRequest,
    startPairingRequest,
    type AuthenticatedDevice,
    type CurrentSession,
    type PairingApprovalRequest,
    type PairingRequestStart,
} from './pairingApi';
import {
    DeviceKeyMissingError,
    DeviceStorageUnavailableError,
    deviceKeyStatus,
    type DeviceIdentity,
    getOrCreateDeviceIdentity,
    loadDeviceIdentity,
} from './deviceIdentity';
import TransferConsole from './TransferConsole';

const REQUEST_POLL_INTERVAL_MS = 2_000;
const PENDING_REQUEST_REFRESH_INTERVAL_MS = 5_000;

type NewBrowserState =
    | 'idle'
    | 'submitting'
    | 'pending'
    | 'completing'
    | 'complete'
    | 'rejected'
    | 'expired';

type TrustedDeviceState = 'checking' | 'ready' | 'signed-out' | 'error';

function formatFingerprint(fingerprint: string): string {
    if (fingerprint.length <= 20) {
        return fingerprint;
    }
    return `${fingerprint.slice(0, 10)}…${fingerprint.slice(-10)}`;
}

function formatCode(code: string): string {
    return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
}

function formatDate(value: string): string {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return 'Unknown time';
    }
    return new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
    }).format(date);
}

function formatRemaining(value: string, now: number): string {
    const remainingSeconds = Math.ceil((new Date(value).getTime() - now) / 1_000);
    if (!Number.isFinite(remainingSeconds) || remainingSeconds <= 0) {
        return 'Expired';
    }
    const minutes = Math.floor(remainingSeconds / 60);
    const seconds = remainingSeconds % 60;
    return `${minutes}:${seconds.toString().padStart(2, '0')} remaining`;
}

function randomNonce(): Uint8Array {
    if (!globalThis.crypto?.getRandomValues) {
        throw new DeviceStorageUnavailableError('Web Crypto is unavailable in this browser.');
    }
    const nonce = new Uint8Array(32);
    globalThis.crypto.getRandomValues(nonce);
    return nonce;
}

function errorMessage(error: unknown, fallback: string): string {
    if (error instanceof ApiError) {
        if (error.status === 0) {
            return 'The secure transfer service is unreachable. Check the connection and try again.';
        }
        if (error.status === 401 || error.status === 403) {
            return 'This request could not be authorized. Refresh the page or sign in again.';
        }
        return error.detail;
    }
    if (error instanceof DeviceKeyMissingError) {
        return error.message;
    }
    if (error instanceof DeviceStorageUnavailableError) {
        return error.message;
    }
    if (error instanceof Error && error.message) {
        return error.message;
    }
    return fallback;
}

function DeviceStatus() {
    const [status, setStatus] = useState<'checking' | 'available' | 'missing'>('checking');

    useEffect(() => {
        let mounted = true;
        void deviceKeyStatus()
            .then((nextStatus) => {
                if (mounted) {
                    setStatus(nextStatus);
                }
            })
            .catch(() => {
                if (mounted) {
                    setStatus('missing');
                }
            });
        return () => {
            mounted = false;
        };
    }, []);

    const statusCopy = {
        available: 'Device key ready',
        missing: 'Device key not found',
        checking: 'Checking device key',
    }[status];

    return (
        <span className={`status-chip status-chip-${status}`} data-testid="device-key-status">
            <span className="status-dot" aria-hidden="true" />
            {statusCopy}
        </span>
    );
}

function NewBrowserPairing() {
    const [email, setEmail] = useState('');
    const [label, setLabel] = useState('This browser');
    const [state, setState] = useState<NewBrowserState>('idle');
    const [request, setRequest] = useState<PairingRequestStart | null>(null);
    const [identity, setIdentity] = useState<DeviceIdentity | null>(null);
    const [completedDevice, setCompletedDevice] = useState<AuthenticatedDevice | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [pollNotice, setPollNotice] = useState<string | null>(null);
    const [now, setNow] = useState(() => Date.now());

    useEffect(() => {
        if (state !== 'pending' && state !== 'completing') {
            return undefined;
        }
        const timer = window.setInterval(() => setNow(Date.now()), 1_000);
        return () => window.clearInterval(timer);
    }, [state]);

    useEffect(() => {
        if (!request || !identity || state !== 'pending') {
            return undefined;
        }
        let cancelled = false;
        let completionStarted = false;

        const poll = async () => {
            try {
                const next = await getPairingRequestStatus(request.request_id);
                if (cancelled) {
                    return;
                }
                setPollNotice(null);
                if (next.status === 'rejected') {
                    setState('rejected');
                    return;
                }
                if (next.status === 'expired') {
                    setState('expired');
                    return;
                }
                if (next.status !== 'approved' || !next.payload || completionStarted) {
                    return;
                }
                completionStarted = true;
                setState('completing');
                try {
                    const result = await completePairingRequest(
                        next,
                        identity.publicKeySpki,
                        identity.fingerprint,
                        identity,
                    );
                    if (cancelled) {
                        return;
                    }
                    setCompletedDevice(result.device);
                    setState('complete');
                } catch (completionError) {
                    if (!cancelled) {
                        setError(
                            errorMessage(completionError, 'The pairing could not be completed.'),
                        );
                        setState('idle');
                    }
                }
            } catch (pollError) {
                if (!cancelled) {
                    setPollNotice(errorMessage(pollError, 'Waiting for the service…'));
                }
            }
        };

        void poll();
        const timer = window.setInterval(() => void poll(), REQUEST_POLL_INTERVAL_MS);
        return () => {
            cancelled = true;
            window.clearInterval(timer);
        };
    }, [identity, request, state]);

    const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        setState('submitting');
        setError(null);
        setPollNotice(null);
        setCompletedDevice(null);
        try {
            const nextIdentity = await getOrCreateDeviceIdentity();
            const created = await startPairingRequest(
                email.trim(),
                nextIdentity.publicKeySpki,
                nextIdentity.fingerprint,
                label.trim(),
            );
            setIdentity(nextIdentity);
            setRequest(created);
            setState('pending');
        } catch (submitError) {
            setError(errorMessage(submitError, 'The pairing request could not be created.'));
            setState('idle');
        }
    };

    const reset = () => {
        setRequest(null);
        setCompletedDevice(null);
        setPollNotice(null);
        setError(null);
        setState('idle');
    };

    if (!request || state === 'idle' || state === 'submitting') {
        return (
            <section className="pairing-panel" aria-labelledby="new-browser-title">
                <div className="panel-heading">
                    <p className="section-kicker">New browser</p>
                    <h2 id="new-browser-title">Bring this browser into your account</h2>
                    <p>
                        Generate a local device key, then ask a trusted device to approve this
                        browser. No session is created until that key proves possession.
                    </p>
                </div>
                <form className="pairing-form" onSubmit={handleSubmit}>
                    <label htmlFor="pairing-email">
                        Account email
                        <input
                            id="pairing-email"
                            name="email"
                            type="email"
                            autoComplete="email"
                            value={email}
                            onChange={(event) => setEmail(event.target.value)}
                            placeholder="you@example.com"
                            required
                            maxLength={320}
                            disabled={state === 'submitting'}
                        />
                    </label>
                    <label htmlFor="pairing-label">
                        Browser label
                        <input
                            id="pairing-label"
                            name="label"
                            type="text"
                            value={label}
                            onChange={(event) => setLabel(event.target.value)}
                            placeholder="This browser"
                            required
                            maxLength={100}
                            disabled={state === 'submitting'}
                        />
                    </label>
                    {error && (
                        <p className="inline-message inline-message-error" role="alert">
                            {error}
                        </p>
                    )}
                    <button
                        className="button button-primary"
                        type="submit"
                        disabled={state === 'submitting'}
                    >
                        {state === 'submitting'
                            ? 'Creating secure request…'
                            : 'Create pairing request'}
                    </button>
                </form>
            </section>
        );
    }

    const isTerminal = state === 'complete' || state === 'rejected' || state === 'expired';
    const statusLabel = {
        pending: 'Waiting for approval',
        completing: 'Finishing enrollment',
        complete: 'Browser trusted',
        rejected: 'Request rejected',
        expired: 'Request expired',
        idle: 'Ready',
        submitting: 'Creating request',
    }[state];

    return (
        <section className="pairing-panel" aria-labelledby="pairing-code-title">
            <div className="panel-heading panel-heading-row">
                <div>
                    <p className="section-kicker">New browser · {statusLabel}</p>
                    <h2 id="pairing-code-title">
                        {state === 'complete' ? 'You’re ready to transfer' : 'Compare this request'}
                    </h2>
                </div>
                <span className={`request-state request-state-${state}`} role="status">
                    <span className="status-dot" aria-hidden="true" />
                    {statusLabel}
                </span>
            </div>
            {state === 'complete' && completedDevice ? (
                <div className="completion-card">
                    <span className="completion-mark" aria-hidden="true">
                        ✓
                    </span>
                    <div>
                        <strong>{completedDevice.label} is trusted</strong>
                        <p>Your secure session is active. You can close this page or continue.</p>
                    </div>
                </div>
            ) : (
                <>
                    <div
                        className="comparison-code"
                        aria-label={`Pairing code ${request.comparison_code}`}
                    >
                        <span className="comparison-code-label">Comparison code</span>
                        <strong>{formatCode(request.comparison_code)}</strong>
                        <span className="comparison-code-help">
                            Read this code to the trusted device before it approves.
                        </span>
                    </div>
                    <dl className="request-details">
                        <div>
                            <dt>Browser label</dt>
                            <dd>{label}</dd>
                        </div>
                        <div>
                            <dt>Device fingerprint</dt>
                            <dd>
                                <code title={identity?.fingerprint}>
                                    {formatFingerprint(
                                        identity?.fingerprint ?? request.fingerprint,
                                    )}
                                </code>
                            </dd>
                        </div>
                        <div>
                            <dt>Created</dt>
                            <dd>{formatDate(request.created_at)}</dd>
                        </div>
                        <div>
                            <dt>Expires</dt>
                            <dd>{formatRemaining(request.expires_at, now)}</dd>
                        </div>
                    </dl>
                    {state === 'pending' && (
                        <p
                            className="inline-message inline-message-neutral"
                            role="status"
                            aria-live="polite"
                        >
                            {pollNotice ??
                                'Keep this window open while your trusted device reviews the request.'}
                        </p>
                    )}
                    {state === 'rejected' && (
                        <p className="inline-message inline-message-warning" role="alert">
                            The trusted device rejected this request. Create a new request if you
                            still want to pair.
                        </p>
                    )}
                    {state === 'expired' && (
                        <p className="inline-message inline-message-warning" role="alert">
                            This request reached its ten-minute limit. Create a new request to try
                            again.
                        </p>
                    )}
                    {error && (
                        <p className="inline-message inline-message-error" role="alert">
                            {error}
                        </p>
                    )}
                </>
            )}
            {isTerminal && (
                <button className="button button-secondary" type="button" onClick={reset}>
                    Start another pairing
                </button>
            )}
        </section>
    );
}

function TrustedDevicePairing() {
    const [session, setSession] = useState<CurrentSession | null>(null);
    const [requests, setRequests] = useState<PairingApprovalRequest[]>([]);
    const [state, setState] = useState<TrustedDeviceState>('checking');
    const [codes, setCodes] = useState<Record<string, string>>({});
    const [busyRequestId, setBusyRequestId] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [notice, setNotice] = useState<string | null>(null);

    const refresh = useCallback(async () => {
        try {
            const current = await getCurrentSession();
            const pending = await listPendingPairingRequests();
            setSession(current);
            setRequests(
                pending.map((request) => ({
                    ...request,
                    account_id: current.account_id,
                    account_device_epoch: current.account_device_epoch,
                })),
            );
            setState('ready');
            setError(null);
        } catch (refreshError) {
            if (refreshError instanceof ApiError && refreshError.status === 401) {
                setSession(null);
                setRequests([]);
                setState('signed-out');
                setError(null);
                return;
            }
            setState('error');
            setError(errorMessage(refreshError, 'Pending requests could not be loaded.'));
        }
    }, []);

    useEffect(() => {
        void refresh();
    }, [refresh]);

    useEffect(() => {
        if (!session) {
            return undefined;
        }
        const timer = window.setInterval(() => void refresh(), PENDING_REQUEST_REFRESH_INTERVAL_MS);
        return () => window.clearInterval(timer);
    }, [refresh, session]);

    const handleApprove = async (pairingRequest: PairingApprovalRequest) => {
        const comparisonCode = codes[pairingRequest.request_id] ?? '';
        if (!/^\d{6}$/u.test(comparisonCode)) {
            setError('Enter the six-digit code shown on the new browser.');
            return;
        }
        setBusyRequestId(pairingRequest.request_id);
        setError(null);
        setNotice(null);
        try {
            const identity = await loadDeviceIdentity();
            if (!identity) {
                throw new DeviceKeyMissingError(
                    'This trusted browser no longer has its device key. Restore site data before approving.',
                );
            }
            await approvePairingRequest(pairingRequest, comparisonCode, randomNonce(), identity);
            setRequests((current) =>
                current.filter((request) => request.request_id !== pairingRequest.request_id),
            );
            setCodes((current) => {
                const next = { ...current };
                delete next[pairingRequest.request_id];
                return next;
            });
            setNotice(
                `${pairingRequest.requested_label} was approved. The new browser can finish enrollment.`,
            );
        } catch (approveError) {
            setError(errorMessage(approveError, 'The pairing request could not be approved.'));
        } finally {
            setBusyRequestId(null);
        }
    };

    const handleReject = async (pairingRequest: PairingApprovalRequest) => {
        setBusyRequestId(pairingRequest.request_id);
        setError(null);
        setNotice(null);
        try {
            await rejectPairingRequest(pairingRequest.request_id);
            setRequests((current) =>
                current.filter((request) => request.request_id !== pairingRequest.request_id),
            );
            setNotice(`${pairingRequest.requested_label} was rejected.`);
        } catch (rejectError) {
            setError(errorMessage(rejectError, 'The pairing request could not be rejected.'));
        } finally {
            setBusyRequestId(null);
        }
    };

    if (state === 'checking') {
        return (
            <section className="pairing-panel empty-panel" aria-labelledby="trusted-device-title">
                <p className="section-kicker">Trusted device</p>
                <h2 id="trusted-device-title">Looking for a trusted session…</h2>
                <p className="empty-copy">Checking whether this browser can approve new devices.</p>
            </section>
        );
    }

    if (state === 'signed-out') {
        return (
            <section className="pairing-panel empty-panel" aria-labelledby="trusted-device-title">
                <p className="section-kicker">Trusted device</p>
                <h2 id="trusted-device-title">Sign in on this browser first</h2>
                <p className="empty-copy">
                    Only a current trusted session can approve a new browser. Return here after
                    signing in with this device key.
                </p>
                <button
                    className="button button-secondary"
                    type="button"
                    onClick={() => void refresh()}
                >
                    Check again
                </button>
            </section>
        );
    }

    return (
        <section className="pairing-panel" aria-labelledby="trusted-device-title">
            <div className="panel-heading panel-heading-row">
                <div>
                    <p className="section-kicker">Trusted device</p>
                    <h2 id="trusted-device-title">Review new browser requests</h2>
                    <p>
                        Compare the code you heard with the request details, then approve the exact
                        key.
                    </p>
                </div>
                <button
                    className="button button-small"
                    type="button"
                    onClick={() => void refresh()}
                >
                    Refresh
                </button>
            </div>
            {error && (
                <p className="inline-message inline-message-error" role="alert">
                    {error}
                </p>
            )}
            {notice && (
                <p className="inline-message inline-message-success" role="status">
                    {notice}
                </p>
            )}
            {requests.length === 0 ? (
                <div className="empty-state">
                    <span className="empty-glyph" aria-hidden="true">
                        ⌁
                    </span>
                    <strong>No pending browsers</strong>
                    <p>New pairing requests will appear here automatically.</p>
                </div>
            ) : (
                <div className="request-list">
                    {requests.map((pairingRequest) => {
                        const busy = busyRequestId === pairingRequest.request_id;
                        const code = codes[pairingRequest.request_id] ?? '';
                        return (
                            <article className="trusted-request" key={pairingRequest.request_id}>
                                <div className="trusted-request-heading">
                                    <div>
                                        <span className="request-label">New browser</span>
                                        <h3>{pairingRequest.requested_label}</h3>
                                    </div>
                                    <span className="request-expiry">
                                        {formatRemaining(pairingRequest.expires_at, Date.now())}
                                    </span>
                                </div>
                                <dl className="request-details request-details-compact">
                                    <div>
                                        <dt>Comparison</dt>
                                        <dd>Enter the code from the other screen</dd>
                                    </div>
                                    <div>
                                        <dt>Fingerprint</dt>
                                        <dd>
                                            <code title={pairingRequest.requested_fingerprint}>
                                                {formatFingerprint(
                                                    pairingRequest.requested_fingerprint,
                                                )}
                                            </code>
                                        </dd>
                                    </div>
                                    <div>
                                        <dt>Requested</dt>
                                        <dd>{formatDate(pairingRequest.created_at)}</dd>
                                    </div>
                                </dl>
                                <label
                                    className="comparison-input-label"
                                    htmlFor={`code-${pairingRequest.request_id}`}
                                >
                                    Six-digit code
                                    <input
                                        id={`code-${pairingRequest.request_id}`}
                                        inputMode="numeric"
                                        autoComplete="one-time-code"
                                        pattern="[0-9]{6}"
                                        maxLength={6}
                                        value={code}
                                        onChange={(event) => {
                                            const nextCode = event.target.value
                                                .replace(/\D/gu, '')
                                                .slice(0, 6);
                                            setCodes((current) => ({
                                                ...current,
                                                [pairingRequest.request_id]: nextCode,
                                            }));
                                        }}
                                        disabled={busy}
                                    />
                                </label>
                                <div className="request-actions">
                                    <button
                                        className="button button-primary"
                                        type="button"
                                        onClick={() => void handleApprove(pairingRequest)}
                                        disabled={busy || code.length !== 6}
                                    >
                                        {busy ? 'Working…' : 'Approve browser'}
                                    </button>
                                    <button
                                        className="button button-danger"
                                        type="button"
                                        onClick={() => void handleReject(pairingRequest)}
                                        disabled={busy}
                                    >
                                        Reject
                                    </button>
                                </div>
                            </article>
                        );
                    })}
                </div>
            )}
        </section>
    );
}

function PairingConsole() {
    const [view, setView] = useState<'new-browser' | 'trusted-device' | 'transfers'>('new-browser');

    return (
        <div className="app-frame">
            <header className="app-header">
                <div className="brand-lockup">
                    <span className="brand-mark" aria-hidden="true">
                        ↗
                    </span>
                    <div>
                        <p className="brand-kicker">E2E / secure transfer</p>
                        <p className="brand-name">Device desk</p>
                    </div>
                </div>
                <DeviceStatus />
            </header>
            <div className="console-intro">
                <p className="eyebrow">Trusted-device pairing</p>
                <h1>Move a browser into the circle of trust.</h1>
                <p>
                    Pairing is a two-screen check: one browser asks, another browser verifies the
                    exact device key. The comparison code is never enough on its own.
                </p>
            </div>
            <nav className="view-tabs" aria-label="Pairing mode">
                <button
                    className={view === 'new-browser' ? 'tab tab-active' : 'tab'}
                    type="button"
                    aria-selected={view === 'new-browser'}
                    onClick={() => setView('new-browser')}
                >
                    Add this browser
                    <span>Request approval</span>
                </button>
                <button
                    className={view === 'trusted-device' ? 'tab tab-active' : 'tab'}
                    type="button"
                    aria-selected={view === 'trusted-device'}
                    onClick={() => setView('trusted-device')}
                >
                    Approve a browser
                    <span>Review requests</span>
                </button>
                <button
                    className={view === 'transfers' ? 'tab tab-active' : 'tab'}
                    type="button"
                    aria-selected={view === 'transfers'}
                    onClick={() => setView('transfers')}
                >
                    Transfer devices
                    <span>Presence and connection test</span>
                </button>
            </nav>
            {view === 'new-browser' ? (
                <NewBrowserPairing />
            ) : view === 'trusted-device' ? (
                <TrustedDevicePairing />
            ) : (
                <TransferConsole />
            )}
            <footer className="console-footer">
                <span>Private keys stay in this browser.</span>
                <span>Requests expire after ten minutes.</span>
            </footer>
        </div>
    );
}

function App() {
    return (
        <main className="health-page">
            <PairingConsole />
        </main>
    );
}

export default App;
