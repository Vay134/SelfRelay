import { type FormEvent, useCallback, useEffect, useState } from 'react';

import {
    completeDeviceLink,
    completeDeviceLogin,
    completeRegistration,
    issueDeviceLinkingChallenge,
    issueDeviceLinkingOtp,
    issueDeviceLoginChallenge,
    issueRegistrationChallenge,
    listDevices,
    logoutDevice,
    renameDevice,
    startOtp,
    verifyOtp,
    type DeviceLinkingOtp,
    type DeviceLoginChallenge,
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
    loadDeviceIdentity,
    type DeviceIdentity,
} from './deviceIdentity';

type AccountView =
    | 'checking'
    | 'signed-out'
    | 'email'
    | 'otp-sent'
    | 'verified'
    | 'linking'
    | 'challenge'
    | 'login-challenge'
    | 'authenticated'
    | 'error';

const ACCOUNT_ID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

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

function deviceStatus(device: AuthenticatedDevice): string {
    return device.status === 'active'
        ? 'Active'
        : device.status === 'revoked'
          ? 'Revoked'
          : 'Logged out';
}

function sortedDevices(devices: AuthenticatedDevice[]): AuthenticatedDevice[] {
    return [...devices].sort((left, right) => {
        const activeDifference =
            Number(right.status === 'active') - Number(left.status === 'active');
        return activeDifference || right.last_seen_at.localeCompare(left.last_seen_at);
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
    const [email, setEmail] = useState('');
    const [otp, setOtp] = useState('');
    const [linkingCode, setLinkingCode] = useState('');
    const [accountId, setAccountId] = useState('');
    const [label, setLabel] = useState(() => getDefaultDeviceLabel());
    const [bootstrap, setBootstrap] = useState<OtpBootstrap | null>(null);
    const [challenge, setChallenge] = useState<RegistrationChallenge | null>(null);
    const [loginChallenge, setLoginChallenge] = useState<DeviceLoginChallenge | null>(null);
    const [identity, setIdentity] = useState<DeviceIdentity | null>(null);
    const [linkingOtp, setLinkingOtp] = useState<DeviceLinkingOtp | null>(null);
    const [busy, setBusy] = useState(false);
    const [busyDeviceId, setBusyDeviceId] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [notice, setNotice] = useState<string | null>(null);

    const refresh = useCallback(async () => {
        try {
            const current = await getCurrentSession();
            const nextDevices = await listDevices();
            setSession(current);
            setDevices(nextDevices);
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

    const handleStartLogin = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const nextAccountId = accountId.trim();
        if (!ACCOUNT_ID_PATTERN.test(nextAccountId)) {
            setError('Enter the account ID shown on a signed-in device.');
            return;
        }
        void run(async () => {
            const nextIdentity = await loadDeviceIdentity();
            if (!nextIdentity) {
                throw new DeviceKeyMissingError('This browser does not have a trusted device key.');
            }
            const nextChallenge = await issueDeviceLoginChallenge(nextAccountId, nextIdentity);
            setIdentity(nextIdentity);
            setLoginChallenge(nextChallenge);
            setView('login-challenge');
        }, 'This browser key could not start a sign-in.');
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

    const completeLogin = () => {
        if (!loginChallenge || !identity) {
            return;
        }
        void run(async () => {
            const result = await completeDeviceLogin(loginChallenge, identity);
            setNotice(
                result.fallback
                    ? 'Email fallback signed in this browser.'
                    : 'Signed in with this browser key.',
            );
            setLoginChallenge(null);
            setIdentity(null);
            await refresh();
        }, 'This browser key could not sign you in.');
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
        ) : view === 'login-challenge' && loginChallenge ? (
            <section className="account-panel" aria-labelledby="login-challenge-title">
                <div className="panel-heading">
                    <p className="section-kicker">Saved browser key</p>
                    <h2 id="login-challenge-title">Confirm this sign-in</h2>
                    <p>Sign the fresh challenge with this browser's non-exportable key.</p>
                </div>
                <dl className="account-id-card">
                    <div>
                        <dt>Account ID</dt>
                        <dd>
                            <code>{loginChallenge.account_id}</code>
                        </dd>
                    </div>
                    <div>
                        <dt>Challenge</dt>
                        <dd>{`Expires ${formatDate(loginChallenge.expires_at)}`}</dd>
                    </div>
                </dl>
                <div className="request-actions">
                    <button
                        className="button button-primary"
                        type="button"
                        onClick={completeLogin}
                        disabled={busy}
                    >
                        {busy ? 'Signing in…' : 'Sign in with this key'}
                    </button>
                </div>
            </section>
        ) : (
            <section className="account-panel" aria-labelledby="access-title">
                <div className="panel-heading">
                    <p className="section-kicker">Account access</p>
                    <h2 id="access-title">Sign in on this browser</h2>
                    <p>
                        Use a saved device key, link this browser from an active device, or use
                        email fallback.
                    </p>
                </div>
                <div className="request-actions">
                    <button
                        className="button button-primary"
                        type="button"
                        onClick={() => setView('email')}
                        disabled={busy}
                    >
                        Use email instead?
                    </button>
                    <button
                        className="button button-secondary"
                        type="button"
                        onClick={() => setView('linking')}
                        disabled={busy}
                    >
                        I have a linking code
                    </button>
                </div>
                <details className="device-login">
                    <summary>Sign in with a saved browser key</summary>
                    <form className="account-form" onSubmit={handleStartLogin}>
                        <label htmlFor="login-account-id">
                            Account ID
                            <input
                                id="login-account-id"
                                type="text"
                                value={accountId}
                                onChange={(event) => setAccountId(event.target.value)}
                                autoComplete="username"
                                placeholder="Account ID from a trusted device"
                                required
                                disabled={busy}
                            />
                        </label>
                        <button className="button button-secondary" type="submit" disabled={busy}>
                            {busy ? 'Checking…' : 'Start key sign-in'}
                        </button>
                    </form>
                </details>
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
        const orderedDevices = sortedDevices(devices);
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
                <section className="account-panel" aria-labelledby="account-title">
                    <div className="panel-heading panel-heading-row">
                        <div>
                            <p className="section-kicker">Trusted devices</p>
                            <h2 id="account-title">Manage your account devices</h2>
                            <p>
                                Active devices can link another browser. Logged-out devices stay
                                listed but cannot authenticate.
                            </p>
                        </div>
                        <button
                            className="button button-secondary"
                            type="button"
                            onClick={() => void refresh()}
                            disabled={busy}
                        >
                            Refresh
                        </button>
                    </div>
                    <div className="account-id-card">
                        <strong>Account ID</strong>
                        <code>{session.account_id}</code>
                        <p>Share this ID only when signing in with a saved browser key.</p>
                    </div>
                    <div className="request-actions">
                        <button
                            className="button button-primary"
                            type="button"
                            onClick={createLinkingCode}
                            disabled={busy}
                        >
                            {busy ? 'Creating…' : 'Create one-time linking code'}
                        </button>
                    </div>
                    {linkingOtp && (
                        <p className="inline-message inline-message-success" role="status">
                            <strong>{linkingOtp.otp}</strong> · expires{' '}
                            {formatDate(linkingOtp.expires_at)} · one use only
                        </p>
                    )}
                    <div className="account-section" aria-labelledby="device-list-title">
                        <div className="transfer-group-heading">
                            <div>
                                <p className="request-label">Device list</p>
                                <h3 id="device-list-title">Active first, logged-out below</h3>
                            </div>
                            <span className="request-expiry">{orderedDevices.length} devices</span>
                        </div>
                        <div className="device-list">
                            {orderedDevices.map((device) => {
                                const current = device.device_id === session.device_id;
                                const active = device.status === 'active';
                                return (
                                    <article
                                        className={`device-card ${active ? '' : 'device-card-muted'}`}
                                        key={device.device_id}
                                    >
                                        <div className="trusted-request-heading">
                                            <div>
                                                <p className="request-label">
                                                    {current ? 'This device' : 'Trusted device'}
                                                </p>
                                                <h3>{device.label}</h3>
                                            </div>
                                            <span
                                                className={`request-state request-state-${active ? 'active' : 'revoked'}`}
                                            >
                                                {deviceStatus(device)}
                                            </span>
                                        </div>
                                        <p className="transfer-copy">
                                            Last seen {formatDate(device.last_seen_at)} · key{' '}
                                            <code>{formatFingerprint(device.fingerprint)}</code>
                                        </p>
                                        {active && (
                                            <form
                                                className="device-rename-form"
                                                onSubmit={(event) => handleRename(device, event)}
                                            >
                                                <label htmlFor={`device-label-${device.device_id}`}>
                                                    Browser label
                                                    <input
                                                        id={`device-label-${device.device_id}`}
                                                        name="label"
                                                        type="text"
                                                        defaultValue={device.label}
                                                        maxLength={100}
                                                        disabled={
                                                            busy ||
                                                            busyDeviceId === device.device_id
                                                        }
                                                    />
                                                </label>
                                                <button
                                                    className="button button-secondary"
                                                    type="submit"
                                                    disabled={
                                                        busy || busyDeviceId === device.device_id
                                                    }
                                                >
                                                    Save label
                                                </button>
                                            </form>
                                        )}
                                        {active && (
                                            <button
                                                className="button button-danger"
                                                type="button"
                                                onClick={() => handleLogoutDevice(device)}
                                                disabled={busy || busyDeviceId === device.device_id}
                                            >
                                                {busyDeviceId === device.device_id
                                                    ? 'Logging out…'
                                                    : current
                                                      ? 'Log out this device'
                                                      : 'Log out remotely'}
                                            </button>
                                        )}
                                    </article>
                                );
                            })}
                        </div>
                    </div>
                </section>
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
            {accessPanel}
        </>
    );
}

export default AccountConsole;
