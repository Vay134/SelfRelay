import { type FormEvent, useCallback, useEffect, useRef, useState } from 'react';

import {
    completeDeviceLink,
    completeRegistration,
    issueDeviceLinkingChallenge,
    issueDeviceLinkingOtp,
    issueRegistrationChallenge,
    listDevices,
    logoutDevice,
    renameDevice,
    startOtp,
    verifyOtp,
    type DeviceLinkingOtp,
    type OtpBootstrap,
    type RegistrationChallenge,
} from './accountApi';
import {
    ApiError,
    clearApiSession,
    getCurrentSession,
    type AuthenticatedDevice,
    type CurrentSession,
} from './pairingApi';
import {
    DeviceKeyMissingError,
    DeviceStorageUnavailableError,
    getDefaultDeviceLabel,
    getOrCreateDeviceIdentity,
    type DeviceIdentity,
} from './deviceIdentity';
import TransferConsole, { type TransferConsoleHandle } from './TransferConsole';
import { listOnlineDevices } from './transferApi';

type AccountView =
    | 'checking'
    | 'signed-out'
    | 'email'
    | 'otp-sent'
    | 'verified'
    | 'linking'
    | 'challenge'
    | 'authenticated'
    | 'error';

function formatFingerprint(value: string): string {
    return value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-12)}` : value;
}

function formatDate(value: string): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? 'Unknown time'
        : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
              date,
          );
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
    if (error instanceof DeviceKeyMissingError || error instanceof DeviceStorageUnavailableError) {
        return error.message;
    }
    return error instanceof Error && error.message ? error.message : fallback;
}

function deviceStatus(device: AuthenticatedDevice, online: boolean): string {
    if (device.status !== 'active') {
        return 'Logged out';
    }
    return online ? 'Online' : 'Offline';
}

// eslint-disable-next-line react-refresh/only-export-components
export function sortDevicesByPresence(
    devices: AuthenticatedDevice[],
    onlineDeviceIds: Set<string>,
): AuthenticatedDevice[] {
    return [...devices].sort((left, right) => {
        const onlineDifference =
            Number(onlineDeviceIds.has(right.device_id)) -
            Number(onlineDeviceIds.has(left.device_id));
        return onlineDifference || right.last_seen_at.localeCompare(left.last_seen_at);
    });
}

function ChallengeReview({
    challenge,
    label,
    busy,
    onConfirm,
}: {
    challenge: RegistrationChallenge;
    label: string;
    busy: boolean;
    onConfirm: () => void;
}) {
    const linked = challenge.enrollment_method === 'device_link';
    return (
        <section className="account-panel" aria-labelledby="challenge-title">
            <div className="panel-heading">
                <p className="section-kicker">{linked ? 'Device linking' : 'Email verified'}</p>
                <h2 id="challenge-title">Confirm this browser key</h2>
                <p>
                    The browser has generated a non-exportable signing key. Confirm its details to
                    {linked ? ' link it to the active account.' : ' register it on this account.'}
                </p>
            </div>
            <dl className="account-id-card">
                <div>
                    <dt>Browser label</dt>
                    <dd>{label}</dd>
                </div>
                <div>
                    <dt>Key fingerprint</dt>
                    <dd>
                        <code>{formatFingerprint(challenge.fingerprint)}</code>
                    </dd>
                </div>
                <div>
                    <dt>Challenge</dt>
                    <dd>{`Expires ${formatDate(challenge.expires_at)}`}</dd>
                </div>
            </dl>
            <div className="request-actions">
                <button
                    className="button button-primary"
                    type="button"
                    onClick={onConfirm}
                    disabled={busy}
                >
                    {busy ? 'Confirming…' : linked ? 'Link this browser' : 'Register this browser'}
                </button>
            </div>
        </section>
    );
}

function AccountConsole() {
    const [view, setView] = useState<AccountView>('checking');
    const [session, setSession] = useState<CurrentSession | null>(null);
    const [devices, setDevices] = useState<AuthenticatedDevice[]>([]);
    const [onlineDeviceIds, setOnlineDeviceIds] = useState<Set<string>>(new Set());
    const [email, setEmail] = useState('');
    const [otp, setOtp] = useState('');
    const [linkingCode, setLinkingCode] = useState('');
    const [label, setLabel] = useState(() => getDefaultDeviceLabel());
    const [bootstrap, setBootstrap] = useState<OtpBootstrap | null>(null);
    const [challenge, setChallenge] = useState<RegistrationChallenge | null>(null);
    const [identity, setIdentity] = useState<DeviceIdentity | null>(null);
    const [linkingOtp, setLinkingOtp] = useState<DeviceLinkingOtp | null>(null);
    const [busy, setBusy] = useState(false);
    const [busyDeviceId, setBusyDeviceId] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [notice, setNotice] = useState<string | null>(null);
    const [transferReady, setTransferReady] = useState(false);
    const transferRef = useRef<TransferConsoleHandle>(null);

    const refresh = useCallback(async () => {
        try {
            const [current, nextDevices, onlineDevices] = await Promise.all([
                getCurrentSession(),
                listDevices(),
                listOnlineDevices(),
            ]);
            setSession(current);
            setDevices(nextDevices);
            setOnlineDeviceIds(new Set(onlineDevices.map((device) => device.device_id)));
            setError(null);
            setView('authenticated');
        } catch (refreshError) {
            if (
                refreshError instanceof ApiError &&
                (refreshError.status === 401 || refreshError.status === 403)
            ) {
                clearApiSession();
                setSession(null);
                setDevices([]);
                setOnlineDeviceIds(new Set());
                setView('signed-out');
                return;
            }
            setError(errorMessage(refreshError, 'Account details are unavailable.'));
            setView('error');
        }
    }, []);

    useEffect(() => {
        void refresh();
    }, [refresh]);

    useEffect(() => {
        if (view !== 'authenticated') {
            return;
        }
        const interval = window.setInterval(() => void refresh(), 15_000);
        return () => window.clearInterval(interval);
    }, [refresh, view]);

    const run = async (action: () => Promise<void>, fallback: string) => {
        setBusy(true);
        setError(null);
        try {
            await action();
        } catch (actionError) {
            setError(errorMessage(actionError, fallback));
        } finally {
            setBusy(false);
        }
    };

    const handleStartOtp = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const nextEmail = email.trim().toLowerCase();
        if (!nextEmail) {
            setError('Enter an email address.');
            return;
        }
        void run(async () => {
            await startOtp(nextEmail);
            setEmail(nextEmail);
            setOtp('');
            setNotice('A one-time code was sent if the address is registered.');
            setView('otp-sent');
        }, 'The email code could not be requested.');
    };

    const handleVerifyOtp = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        void run(async () => {
            const verified = await verifyOtp(email.trim().toLowerCase(), otp.trim());
            setBootstrap(verified);
            setNotice(null);
            setView('verified');
        }, 'The email or one-time code is invalid.');
    };

    const handleEmailRegistration = () => {
        if (!bootstrap) {
            return;
        }
        void run(async () => {
            const nextIdentity = await getOrCreateDeviceIdentity();
            const nextChallenge = await issueRegistrationChallenge(
                bootstrap.bootstrap_token,
                nextIdentity,
                label,
            );
            setIdentity(nextIdentity);
            setChallenge(nextChallenge);
            setView('challenge');
        }, 'This browser could not prepare its signing key.');
    };

    const handleStartLinking = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        void run(async () => {
            const nextIdentity = await getOrCreateDeviceIdentity();
            const nextChallenge = await issueDeviceLinkingChallenge(
                linkingCode.trim(),
                nextIdentity,
                label,
            );
            setIdentity(nextIdentity);
            setChallenge(nextChallenge);
            setView('challenge');
        }, 'The device-linking code is invalid or expired.');
    };

    const completeChallenge = () => {
        if (!challenge || !identity) {
            return;
        }
        void run(async () => {
            const result =
                challenge.enrollment_method === 'device_link'
                    ? await completeDeviceLink(challenge, identity)
                    : await completeRegistration(challenge, identity);
            setNotice(
                result.fallback
                    ? 'Email fallback signed in this browser. Other devices were unchanged.'
                    : 'This browser is now trusted.',
            );
            setBootstrap(null);
            setChallenge(null);
            setIdentity(null);
            await refresh();
        }, 'The browser key proof could not be completed.');
    };

    const createLinkingCode = () => {
        void run(async () => {
            setLinkingOtp(await issueDeviceLinkingOtp());
            setNotice('Enter this one-time code on the browser you want to link.');
        }, 'A device-linking code could not be created.');
    };

    const handleRename = (device: AuthenticatedDevice, event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const input = new FormData(event.currentTarget).get('label');
        const nextLabel = typeof input === 'string' ? input.trim() : '';
        if (!nextLabel) {
            setError('Enter a browser label.');
            return;
        }
        void run(async () => {
            const updated = await renameDevice(device.device_id, nextLabel);
            setDevices((current) =>
                current.map((item) => (item.device_id === updated.device_id ? updated : item)),
            );
            setNotice('Browser label saved.');
        }, 'The browser label could not be saved.');
    };

    const handleLogoutDevice = (device: AuthenticatedDevice) => {
        if (!window.confirm(`Log out ${device.label}?`)) {
            return;
        }
        setBusyDeviceId(device.device_id);
        setError(null);
        void logoutDevice(device.device_id)
            .then((updated) => {
                if (device.device_id === session?.device_id) {
                    clearApiSession();
                    setSession(null);
                    setDevices([]);
                    setView('signed-out');
                    setNotice(
                        'This browser is logged out. Choose email fallback or sign in with its key.',
                    );
                } else {
                    setDevices((current) =>
                        current.map((item) =>
                            item.device_id === updated.device_id ? updated : item,
                        ),
                    );
                    setNotice(`${device.label} is logged out.`);
                }
            })
            .catch((logoutError: unknown) => {
                setError(errorMessage(logoutError, 'The browser could not be logged out.'));
            })
            .finally(() => setBusyDeviceId(null));
    };

    const accessPanel =
        view === 'email' ? (
            <section className="account-panel" aria-labelledby="email-title">
                <div className="panel-heading">
                    <p className="section-kicker">Email fallback</p>
                    <h2 id="email-title">Use email instead?</h2>
                    <p>Verify the account email to sign in or add only this browser.</p>
                </div>
                <form className="account-form" onSubmit={handleStartOtp}>
                    <label htmlFor="account-email">
                        Email address
                        <input
                            id="account-email"
                            type="email"
                            value={email}
                            onChange={(event) => setEmail(event.target.value)}
                            autoComplete="email"
                            required
                            disabled={busy}
                        />
                    </label>
                    <button className="button button-primary" type="submit" disabled={busy}>
                        {busy ? 'Sending…' : 'Send email code'}
                    </button>
                </form>
                <p className="account-help">
                    <button type="button" onClick={() => setView('signed-out')} disabled={busy}>
                        Use a saved browser key instead
                    </button>
                </p>
            </section>
        ) : view === 'otp-sent' ? (
            <section className="account-panel" aria-labelledby="otp-title">
                <div className="panel-heading">
                    <p className="section-kicker">Email code sent</p>
                    <h2 id="otp-title">Enter the code from your email</h2>
                    <p>{email}</p>
                </div>
                <form className="account-form" onSubmit={handleVerifyOtp}>
                    <label htmlFor="account-otp">
                        One-time code
                        <input
                            id="account-otp"
                            type="text"
                            inputMode="numeric"
                            autoComplete="one-time-code"
                            value={otp}
                            onChange={(event) => setOtp(event.target.value)}
                            required
                            disabled={busy}
                        />
                    </label>
                    <button className="button button-primary" type="submit" disabled={busy}>
                        {busy ? 'Checking…' : 'Verify email'}
                    </button>
                </form>
                <p className="account-help">
                    <button type="button" onClick={() => setView('email')} disabled={busy}>
                        Use a different email
                    </button>
                </p>
            </section>
        ) : view === 'verified' ? (
            <section className="account-panel" aria-labelledby="verified-title">
                <div className="panel-heading">
                    <p className="section-kicker">Email verified</p>
                    <h2 id="verified-title">Register this browser</h2>
                    <p>
                        Your email proof is complete. Choose a recognizable label for this browser.
                    </p>
                </div>
                <form
                    className="account-form"
                    onSubmit={(event) => {
                        event.preventDefault();
                        handleEmailRegistration();
                    }}
                >
                    <label htmlFor="verified-device-label">
                        Browser label
                        <input
                            id="verified-device-label"
                            type="text"
                            value={label}
                            onChange={(event) => setLabel(event.target.value)}
                            maxLength={100}
                            required
                            disabled={busy}
                        />
                    </label>
                    <button className="button button-primary" type="submit" disabled={busy}>
                        {busy ? 'Preparing…' : 'Review browser key'}
                    </button>
                </form>
            </section>
        ) : view === 'linking' ? (
            <section className="account-panel" aria-labelledby="linking-title">
                <div className="panel-heading">
                    <p className="section-kicker">Device linking</p>
                    <h2 id="linking-title">Enter the one-time code</h2>
                    <p>
                        Create this code on an active device. It expires after one use or ten
                        minutes.
                    </p>
                </div>
                <form className="account-form" onSubmit={handleStartLinking}>
                    <label htmlFor="linking-code">
                        Device-linking code
                        <input
                            id="linking-code"
                            type="text"
                            inputMode="numeric"
                            autoComplete="one-time-code"
                            value={linkingCode}
                            onChange={(event) => setLinkingCode(event.target.value)}
                            minLength={6}
                            maxLength={6}
                            required
                            disabled={busy}
                        />
                    </label>
                    <label htmlFor="linking-device-label">
                        Browser label
                        <input
                            id="linking-device-label"
                            type="text"
                            value={label}
                            onChange={(event) => setLabel(event.target.value)}
                            maxLength={100}
                            required
                            disabled={busy}
                        />
                    </label>
                    <button className="button button-primary" type="submit" disabled={busy}>
                        {busy ? 'Checking…' : 'Continue with linking code'}
                    </button>
                </form>
            </section>
        ) : view === 'challenge' && challenge ? (
            <ChallengeReview
                challenge={challenge}
                label={label}
                busy={busy}
                onConfirm={completeChallenge}
            />
        ) : (
            <section className="account-panel auth-home" aria-label="Account access">
                <form className="account-form auth-option" onSubmit={handleStartOtp}>
                    <label className="sr-only" htmlFor="account-email-home">
                        Email address
                    </label>
                    <span className="auth-option-mark" aria-hidden="true">
                        @
                    </span>
                    <input
                        id="account-email-home"
                        type="email"
                        value={email}
                        onChange={(event) => setEmail(event.target.value)}
                        autoComplete="email"
                        placeholder="Email address"
                        required
                        disabled={busy}
                    />
                    <button className="button button-primary" type="submit" disabled={busy}>
                        {busy ? 'Sending…' : 'Continue'}
                    </button>
                </form>
                <div className="auth-divider" role="separator">
                    <span>or</span>
                </div>
                <form className="account-form auth-option" onSubmit={handleStartLinking}>
                    <label className="sr-only" htmlFor="linking-code-home">
                        One-time code from another device
                    </label>
                    <span className="auth-option-mark" aria-hidden="true">
                        ↔
                    </span>
                    <input
                        id="linking-code-home"
                        type="text"
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        value={linkingCode}
                        onChange={(event) => setLinkingCode(event.target.value)}
                        minLength={6}
                        maxLength={6}
                        placeholder="Device code"
                        required
                        disabled={busy}
                    />
                    <button className="button button-secondary" type="submit" disabled={busy}>
                        {busy ? 'Linking…' : 'Link'}
                    </button>
                </form>
            </section>
        );

    if (view === 'checking') {
        return (
            <section className="account-panel empty-panel" aria-labelledby="account-checking-title">
                <p className="section-kicker">Account access</p>
                <h2 id="account-checking-title">Checking this browser session…</h2>
                <p className="empty-copy">Looking for an active trusted-device session.</p>
            </section>
        );
    }

    if (view === 'authenticated' && session) {
        const currentDevice = devices.find((device) => device.device_id === session.device_id);
        const orderedDevices = sortDevicesByPresence(
            devices.filter((device) => device.device_id !== session.device_id),
            onlineDeviceIds,
        );
        const onlineCount = orderedDevices.filter((device) =>
            onlineDeviceIds.has(device.device_id),
        ).length;
        return (
            <>
                {error && (
                    <p
                        className="inline-message inline-message-error account-global-message"
                        role="alert"
                    >
                        {error}
                    </p>
                )}
                {notice && (
                    <p
                        className="inline-message inline-message-success account-global-message"
                        role="status"
                    >
                        {notice}
                    </p>
                )}
                <section className="account-panel devices-panel" aria-labelledby="account-title">
                    <div className="panel-heading panel-heading-row dashboard-heading">
                        <div>
                            <p className="section-kicker">Your devices</p>
                            <h1 id="account-title">Where do you want to send?</h1>
                            <p>Online devices appear first. Presence refreshes automatically.</p>
                        </div>
                        <button
                            className="button button-quiet"
                            type="button"
                            onClick={() => void refresh()}
                            disabled={busy}
                        >
                            Refresh now
                        </button>
                    </div>

                    {currentDevice && (
                        <div className="current-device" aria-label="Current device">
                            <div>
                                <span className="request-label">This device</span>
                                <strong>{currentDevice.label}</strong>
                            </div>
                            <form
                                className="current-device-actions"
                                onSubmit={(event) => handleRename(currentDevice, event)}
                            >
                                <label className="sr-only" htmlFor="current-device-label">
                                    Current device name
                                </label>
                                <input
                                    id="current-device-label"
                                    name="label"
                                    type="text"
                                    defaultValue={currentDevice.label}
                                    maxLength={100}
                                    disabled={busy}
                                />
                                <button
                                    className="button button-secondary"
                                    type="submit"
                                    disabled={busy}
                                >
                                    Rename
                                </button>
                                <button
                                    className="button button-quiet button-danger-text"
                                    type="button"
                                    onClick={() => handleLogoutDevice(currentDevice)}
                                    disabled={busy}
                                >
                                    Log out
                                </button>
                            </form>
                        </div>
                    )}

                    <div className="account-section" aria-labelledby="device-list-title">
                        <div className="transfer-group-heading">
                            <div>
                                <p className="request-label">Connected devices</p>
                                <h2 id="device-list-title">Ready when you are</h2>
                            </div>
                            <span className="request-expiry">
                                {onlineCount} online · {orderedDevices.length} total
                            </span>
                        </div>
                        <div className="device-list">
                            {orderedDevices.length === 0 && (
                                <div className="empty-state">
                                    <strong>No other devices yet</strong>
                                    <p>
                                        Create a one-time code, then enter it on your other device.
                                    </p>
                                </div>
                            )}
                            {orderedDevices.map((device) => {
                                const trusted = device.status === 'active';
                                const online = trusted && onlineDeviceIds.has(device.device_id);
                                return (
                                    <article
                                        className={`device-card ${online ? '' : 'device-card-muted'}`}
                                        key={device.device_id}
                                    >
                                        <span
                                            className={`device-presence ${online ? 'device-presence-online' : ''}`}
                                            aria-hidden="true"
                                        />
                                        <div className="device-content">
                                            <form
                                                className="device-name-editor"
                                                onSubmit={(event) => handleRename(device, event)}
                                            >
                                                <label
                                                    className="sr-only"
                                                    htmlFor={`device-label-${device.device_id}`}
                                                >
                                                    Device name
                                                </label>
                                                <input
                                                    id={`device-label-${device.device_id}`}
                                                    name="label"
                                                    type="text"
                                                    defaultValue={device.label}
                                                    maxLength={100}
                                                    disabled={
                                                        !trusted ||
                                                        busy ||
                                                        busyDeviceId === device.device_id
                                                    }
                                                />
                                                {trusted && (
                                                    <button
                                                        className="rename-link"
                                                        type="submit"
                                                        disabled={busy}
                                                    >
                                                        Save name
                                                    </button>
                                                )}
                                            </form>
                                            <span
                                                className={`request-state request-state-${online ? 'active' : 'revoked'}`}
                                            >
                                                {deviceStatus(device, online)} · Last seen{' '}
                                                {formatDate(device.last_seen_at)}
                                            </span>
                                            <div className="device-actions">
                                                <button
                                                    className="button button-primary"
                                                    type="button"
                                                    onClick={() =>
                                                        transferRef.current?.startTransfer(
                                                            device.device_id,
                                                        )
                                                    }
                                                    disabled={!online || !transferReady || busy}
                                                >
                                                    {!online
                                                        ? 'Offline'
                                                        : transferReady
                                                          ? 'Transfer'
                                                          : 'Connecting…'}
                                                </button>
                                                <button
                                                    className="button button-secondary"
                                                    type="button"
                                                    onClick={() => handleLogoutDevice(device)}
                                                    disabled={
                                                        !trusted ||
                                                        busy ||
                                                        busyDeviceId === device.device_id
                                                    }
                                                >
                                                    {busyDeviceId === device.device_id
                                                        ? 'Logging out…'
                                                        : trusted
                                                          ? 'Log out device'
                                                          : 'Logged out'}
                                                </button>
                                            </div>
                                        </div>
                                    </article>
                                );
                            })}
                        </div>
                    </div>

                    <details className="account-tools">
                        <summary>Link another device</summary>
                        <p>Create a six-digit code, then enter it on the new device.</p>
                        <button
                            className="button button-secondary"
                            type="button"
                            onClick={createLinkingCode}
                            disabled={busy}
                        >
                            {busy ? 'Creating…' : 'Create one-time code'}
                        </button>
                        {linkingOtp && (
                            <p className="linking-code" role="status">
                                <strong>{linkingOtp.otp}</strong>
                                <span>Expires {formatDate(linkingOtp.expires_at)}</span>
                            </p>
                        )}
                    </details>
                </section>
                <TransferConsole ref={transferRef} embedded onReadyChange={setTransferReady} />
            </>
        );
    }

    return (
        <>
            {error && (
                <p
                    className="inline-message inline-message-error account-global-message"
                    role="alert"
                >
                    {error}
                </p>
            )}
            {notice && (
                <p
                    className="inline-message inline-message-success account-global-message"
                    role="status"
                >
                    {notice}
                </p>
            )}
            <div className="auth-stage">
                <section className="auth-hero" aria-labelledby="selfrelay-title">
                    <h1 className="hero-title" id="selfrelay-title">
                        SelfRelay
                        <svg
                            className="hero-arrow"
                            viewBox="0 0 560 36"
                            aria-hidden="true"
                            focusable="false"
                        >
                            <defs>
                                <marker
                                    id="hero-arrow-tip"
                                    viewBox="0 0 12 12"
                                    refX="9.5"
                                    refY="6"
                                    markerWidth="3.5"
                                    markerHeight="3.5"
                                    orient="auto"
                                    markerUnits="strokeWidth"
                                >
                                    <path className="hero-arrow-head" d="M0 0 L12 6 L0 12 Z" />
                                </marker>
                            </defs>
                            <path
                                d="M4 8 C 176 31 420 34 536 10"
                                markerEnd="url(#hero-arrow-tip)"
                            />
                        </svg>
                    </h1>
                    <p className="hero-description">
                        Secure end-to-end file transfers between your trusted devices.
                    </p>
                    <div className="auth-pane">{accessPanel}</div>
                </section>
            </div>
        </>
    );
}

export default AccountConsole;
