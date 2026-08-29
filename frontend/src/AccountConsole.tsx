import { type FormEvent, useCallback, useEffect, useRef, useState } from 'react';

import {
    completeDeviceLogin,
    completeRegistration,
    issueDeviceLoginChallenge,
    issueRegistrationChallenge,
    listDevices,
    listSessions,
    logout,
    renameDevice,
    revokeDevice,
    startOtp,
    verifyOtp,
    type AuthenticatedSession,
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
    getOrCreateDeviceIdentity,
    loadDeviceIdentity,
    type DeviceIdentity,
} from './deviceIdentity';

type AccountView =
    | 'checking'
    | 'signed-out'
    | 'otp-sent'
    | 'verified'
    | 'challenge'
    | 'login-challenge'
    | 'authenticated'
    | 'error';

type Confirmation = {
    title: string;
    description: string;
    confirmLabel: string;
    danger?: boolean;
    action: () => Promise<void>;
};

const ACCOUNT_ID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function formatFingerprint(fingerprint: string): string {
    if (fingerprint.length <= 20) {
        return fingerprint;
    }
    return `${fingerprint.slice(0, 10)}…${fingerprint.slice(-10)}`;
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

function formatExpiry(value: string): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Unknown expiry' : `Expires ${formatDate(value)}`;
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
    if (error instanceof Error && error.message) {
        return error.message;
    }
    return fallback;
}

function ConfirmDialog({
    confirmation,
    busy,
    onCancel,
    onConfirm,
}: {
    confirmation: Confirmation | null;
    busy: boolean;
    onCancel: () => void;
    onConfirm: () => void;
}) {
    const dialog = useRef<HTMLDivElement>(null);
    const confirmButton = useRef<HTMLButtonElement>(null);
    const previouslyFocused = useRef<HTMLElement | null>(null);

    useEffect(() => {
        if (!confirmation) {
            return undefined;
        }
        previouslyFocused.current =
            document.activeElement instanceof HTMLElement ? document.activeElement : null;
        confirmButton.current?.focus();
        return () => {
            if (previouslyFocused.current?.isConnected) {
                previouslyFocused.current.focus();
            }
        };
    }, [confirmation]);

    useEffect(() => {
        if (!confirmation) {
            return undefined;
        }
        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Escape' && !busy) {
                event.preventDefault();
                onCancel();
                return;
            }
            if (event.key !== 'Tab') {
                return;
            }
            const focusable = dialog.current?.querySelectorAll<HTMLElement>(
                'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
            );
            if (!focusable?.length) {
                event.preventDefault();
                return;
            }
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            const active = document.activeElement;
            if (!dialog.current?.contains(active)) {
                event.preventDefault();
                first.focus();
            } else if (event.shiftKey && active === first) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && active === last) {
                event.preventDefault();
                first.focus();
            }
        };
        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [busy, confirmation, onCancel]);

    if (!confirmation) {
        return null;
    }

    return (
        <div className="dialog-backdrop" role="presentation">
            <div
                ref={dialog}
                className="confirm-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="confirm-dialog-title"
                aria-describedby="confirm-dialog-description"
            >
                <p className="section-kicker">Please confirm</p>
                <h2 id="confirm-dialog-title">{confirmation.title}</h2>
                <p id="confirm-dialog-description">{confirmation.description}</p>
                <div className="request-actions">
                    <button
                        className="button button-secondary"
                        type="button"
                        onClick={onCancel}
                        disabled={busy}
                    >
                        Cancel
                    </button>
                    <button
                        ref={confirmButton}
                        className={`button ${confirmation.danger ? 'button-danger' : 'button-primary'}`}
                        type="button"
                        onClick={onConfirm}
                        disabled={busy}
                    >
                        {busy ? 'Working…' : confirmation.confirmLabel}
                    </button>
                </div>
            </div>
        </div>
    );
}

function OtpAccess({
    view,
    email,
    otp,
    label,
    busy,
    accountId,
    onEmailChange,
    onOtpChange,
    onLabelChange,
    onAccountIdChange,
    onStartOtp,
    onResendOtp,
    onVerifyOtp,
    onStartDeviceLogin,
}: {
    view: AccountView;
    email: string;
    otp: string;
    label: string;
    busy: boolean;
    accountId: string;
    onEmailChange: (value: string) => void;
    onOtpChange: (value: string) => void;
    onLabelChange: (value: string) => void;
    onAccountIdChange: (value: string) => void;
    onStartOtp: (event: FormEvent<HTMLFormElement>) => void;
    onResendOtp: () => void;
    onVerifyOtp: (event: FormEvent<HTMLFormElement>) => void;
    onStartDeviceLogin: (event: FormEvent<HTMLFormElement>) => void;
}) {
    if (view === 'otp-sent') {
        return (
            <section className="account-panel" aria-labelledby="otp-title">
                <div className="panel-heading">
                    <p className="section-kicker">Account access · code sent</p>
                    <h2 id="otp-title">Enter the code from your email</h2>
                    <p>
                        If the address can receive messages, a one-time code is on its way. The code
                        expires soon and is never stored in this browser.
                    </p>
                </div>
                <form className="account-form" onSubmit={onVerifyOtp}>
                    <label htmlFor="account-otp">
                        One-time code
                        <input
                            id="account-otp"
                            name="otp"
                            type="text"
                            inputMode="numeric"
                            autoComplete="one-time-code"
                            value={otp}
                            onChange={(event) => onOtpChange(event.target.value)}
                            required
                            maxLength={64}
                            disabled={busy}
                        />
                    </label>
                    <button className="button button-primary" type="submit" disabled={busy}>
                        {busy ? 'Checking code…' : 'Verify code'}
                    </button>
                </form>
                <p className="account-help">
                    Code not received?{' '}
                    <button type="button" onClick={onResendOtp} disabled={busy}>
                        Send another code
                    </button>
                </p>
            </section>
        );
    }

    return (
        <section className="account-panel" aria-labelledby="account-access-title">
            <div className="panel-heading">
                <p className="section-kicker">Account access</p>
                <h2 id="account-access-title">Create or recover your account</h2>
                <p>
                    Verify your email, then register this browser with a local device key. The
                    private key stays in this browser profile.
                </p>
            </div>
            <form className="account-form" onSubmit={onStartOtp}>
                <label htmlFor="account-email">
                    Account email
                    <input
                        id="account-email"
                        name="email"
                        type="email"
                        autoComplete="email"
                        value={email}
                        onChange={(event) => onEmailChange(event.target.value)}
                        placeholder="you@example.com"
                        required
                        maxLength={320}
                        disabled={busy}
                    />
                </label>
                <label htmlFor="account-device-label">
                    Browser label
                    <input
                        id="account-device-label"
                        name="label"
                        type="text"
                        value={label}
                        onChange={(event) => onLabelChange(event.target.value)}
                        placeholder="This browser"
                        required
                        maxLength={100}
                        disabled={busy}
                    />
                </label>
                <button className="button button-primary" type="submit" disabled={busy}>
                    {busy ? 'Sending code…' : 'Email me a sign-in code'}
                </button>
            </form>
            <details className="device-login">
                <summary>Use a trusted browser key</summary>
                <p>
                    If this browser was already registered, sign in by proving possession of its
                    local key. You will need your account ID from a previous signed-in session.
                </p>
                <form className="account-form" onSubmit={onStartDeviceLogin}>
                    <label htmlFor="account-id">
                        Account ID
                        <input
                            id="account-id"
                            name="account-id"
                            type="text"
                            inputMode="text"
                            autoComplete="off"
                            value={accountId}
                            onChange={(event) => onAccountIdChange(event.target.value)}
                            placeholder="xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
                            pattern={ACCOUNT_ID_PATTERN.source}
                            required
                            disabled={busy}
                        />
                    </label>
                    <button className="button button-secondary" type="submit" disabled={busy}>
                        Use this device key
                    </button>
                </form>
            </details>
        </section>
    );
}

function EnrollmentReview({
    challenge,
    identity,
    label,
    recovery,
    busy,
    onConfirm,
}: {
    challenge: RegistrationChallenge;
    identity: DeviceIdentity;
    label: string;
    recovery: boolean;
    busy: boolean;
    onConfirm: () => void;
}) {
    return (
        <section className="account-panel" aria-labelledby="enrollment-title">
            <div className="panel-heading">
                <p className="section-kicker">{recovery ? 'Recovery' : 'New device'}</p>
                <h2 id="enrollment-title">Review this browser before trusting it</h2>
                <p>
                    Check the device fingerprint before the browser receives an authenticated
                    session. This proof is bound to this browser&apos;s non-exportable private key.
                </p>
            </div>
            <dl className="request-details">
                <div>
                    <dt>Browser label</dt>
                    <dd>{label}</dd>
                </div>
                <div>
                    <dt>Device fingerprint</dt>
                    <dd>
                        <code title={identity.fingerprint}>
                            {formatFingerprint(identity.fingerprint)}
                        </code>
                    </dd>
                </div>
                <div>
                    <dt>Challenge</dt>
                    <dd>{formatExpiry(challenge.expires_at)}</dd>
                </div>
            </dl>
            {recovery && (
                <p className="inline-message inline-message-warning" role="alert">
                    Recovery revokes every existing device and session. Those browsers will need to
                    pair again.
                </p>
            )}
            <button
                className="button button-primary"
                type="button"
                onClick={onConfirm}
                disabled={busy}
            >
                {busy ? 'Trusting browser…' : 'Trust this browser'}
            </button>
        </section>
    );
}

function DeviceCard({
    device,
    current,
    draftLabel,
    busy,
    onDraftChange,
    onRename,
    onRevoke,
}: {
    device: AuthenticatedDevice;
    current: boolean;
    draftLabel: string;
    busy: boolean;
    onDraftChange: (value: string) => void;
    onRename: (event: FormEvent<HTMLFormElement>) => void;
    onRevoke: () => void;
}) {
    return (
        <article className="device-card">
            <div className="trusted-request-heading">
                <div>
                    <span className="request-label">
                        {current ? 'This browser' : 'Trusted browser'}
                    </span>
                    <h3>{device.label}</h3>
                </div>
                <span className={`request-state request-state-${device.status}`}>
                    <span className="status-dot" aria-hidden="true" />
                    {device.status === 'active' ? 'Active' : device.status}
                </span>
            </div>
            <dl className="request-details request-details-compact">
                <div>
                    <dt>Fingerprint</dt>
                    <dd>
                        <code title={device.fingerprint}>
                            {formatFingerprint(device.fingerprint)}
                        </code>
                    </dd>
                </div>
                <div>
                    <dt>Added</dt>
                    <dd>{formatDate(device.created_at)}</dd>
                </div>
                <div>
                    <dt>Last seen</dt>
                    <dd>{formatDate(device.last_seen_at)}</dd>
                </div>
            </dl>
            {device.status === 'active' && (
                <>
                    <form className="device-rename-form" onSubmit={onRename}>
                        <label htmlFor={`rename-${device.device_id}`}>
                            Browser label
                            <input
                                id={`rename-${device.device_id}`}
                                type="text"
                                value={draftLabel}
                                onChange={(event) => onDraftChange(event.target.value)}
                                maxLength={100}
                                required
                                disabled={busy}
                            />
                        </label>
                        <button
                            className="button button-secondary button-small"
                            type="submit"
                            disabled={busy}
                            aria-label={`Save label for ${device.label}`}
                        >
                            {busy ? 'Saving…' : 'Save label'}
                        </button>
                    </form>
                    <button
                        className="button button-danger"
                        type="button"
                        onClick={onRevoke}
                        disabled={busy}
                        aria-label={`Revoke ${current ? 'this browser' : `${device.label} browser`}`}
                    >
                        Revoke browser
                    </button>
                </>
            )}
        </article>
    );
}

function AccountDashboard({
    session,
    devices,
    sessions,
    drafts,
    busyDeviceId,
    busy,
    onRefresh,
    onDraftChange,
    onRename,
    onRevoke,
    onLogout,
}: {
    session: CurrentSession;
    devices: AuthenticatedDevice[];
    sessions: AuthenticatedSession[];
    drafts: Record<string, string>;
    busyDeviceId: string | null;
    busy: boolean;
    onRefresh: () => void;
    onDraftChange: (deviceId: string, value: string) => void;
    onRename: (device: AuthenticatedDevice, event: FormEvent<HTMLFormElement>) => void;
    onRevoke: (device: AuthenticatedDevice) => void;
    onLogout: () => void;
}) {
    return (
        <section className="account-panel" aria-labelledby="account-title">
            <div className="panel-heading panel-heading-row">
                <div>
                    <p className="section-kicker">Account · trusted devices</p>
                    <h2 id="account-title">Your secure circle</h2>
                    <p>Manage the browsers that can approve pairings and transfer files.</p>
                </div>
                <div className="request-actions account-actions">
                    <button
                        className="button button-small"
                        type="button"
                        onClick={onRefresh}
                        disabled={busy}
                        aria-label="Refresh account details"
                    >
                        Refresh
                    </button>
                    <button
                        className="button button-secondary button-small"
                        type="button"
                        onClick={onLogout}
                        disabled={busy}
                        aria-label="Sign out of this browser"
                    >
                        Sign out
                    </button>
                </div>
            </div>
            <div className="account-id-card">
                <span className="request-label">Account ID</span>
                <code>{session.account_id}</code>
                <p>Keep this ID available if you want to sign in later with this browser key.</p>
            </div>
            <div className="account-section">
                <div className="transfer-group-heading">
                    <h3>Browsers</h3>
                    <span className="request-expiry">{devices.length} registered</span>
                </div>
                {devices.length === 0 ? (
                    <div className="empty-state">
                        <strong>No browsers registered</strong>
                        <p>
                            Register a browser with email recovery or pair one from another trusted
                            browser.
                        </p>
                    </div>
                ) : (
                    <div className="device-list">
                        {devices.map((device) => (
                            <DeviceCard
                                key={device.device_id}
                                device={device}
                                current={device.device_id === session.device_id}
                                draftLabel={drafts[device.device_id] ?? device.label}
                                busy={busyDeviceId === device.device_id}
                                onDraftChange={(value) => onDraftChange(device.device_id, value)}
                                onRename={(event) => onRename(device, event)}
                                onRevoke={() => onRevoke(device)}
                            />
                        ))}
                    </div>
                )}
            </div>
            <div className="account-section">
                <div className="transfer-group-heading">
                    <h3>Sessions</h3>
                    <span className="request-expiry">{sessions.length} recorded</span>
                </div>
                <div className="session-list">
                    {sessions.map((item) => (
                        <div className="session-row" key={item.session_id}>
                            <div>
                                <strong>
                                    {item.device_id === session.device_id
                                        ? 'This browser'
                                        : 'Trusted browser'}
                                </strong>
                                <span>{formatDate(item.last_seen_at)}</span>
                            </div>
                            <span
                                className={`request-state ${item.revoked_at ? 'request-state-revoked' : 'request-state-active'}`}
                            >
                                {item.revoked_at
                                    ? `Ended ${formatDate(item.revoked_at)}`
                                    : 'Active'}
                            </span>
                        </div>
                    ))}
                    {sessions.length === 0 && (
                        <p className="empty-copy">No session history is available.</p>
                    )}
                </div>
            </div>
        </section>
    );
}

function AccountConsole() {
    const [view, setView] = useState<AccountView>('checking');
    const [session, setSession] = useState<CurrentSession | null>(null);
    const [devices, setDevices] = useState<AuthenticatedDevice[]>([]);
    const [sessions, setSessions] = useState<AuthenticatedSession[]>([]);
    const [drafts, setDrafts] = useState<Record<string, string>>({});
    const [busyDeviceId, setBusyDeviceId] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [email, setEmail] = useState('');
    const [otp, setOtp] = useState('');
    const [label, setLabel] = useState('This browser');
    const [accountId, setAccountId] = useState('');
    const [bootstrap, setBootstrap] = useState<OtpBootstrap | null>(null);
    const [identity, setIdentity] = useState<DeviceIdentity | null>(null);
    const [challenge, setChallenge] = useState<RegistrationChallenge | null>(null);
    const [loginChallenge, setLoginChallenge] = useState<DeviceLoginChallenge | null>(null);
    const [recovery, setRecovery] = useState(false);
    const [needsRecovery, setNeedsRecovery] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [notice, setNotice] = useState<string | null>(null);
    const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
    const [confirmationBusy, setConfirmationBusy] = useState(false);

    const refresh = useCallback(async () => {
        try {
            const current = await getCurrentSession();
            const [nextDevices, nextSessions] = await Promise.all([listDevices(), listSessions()]);
            setSession(current);
            setDevices(nextDevices);
            setSessions(nextSessions);
            setDrafts(
                Object.fromEntries(nextDevices.map((device) => [device.device_id, device.label])),
            );
            setView('authenticated');
            setError(null);
        } catch (refreshError) {
            if (refreshError instanceof ApiError && refreshError.status === 401) {
                clearApiSession();
                setSession(null);
                setDevices([]);
                setSessions([]);
                setView('signed-out');
                return;
            }
            setView('error');
            setError(errorMessage(refreshError, 'Account details could not be loaded.'));
        }
    }, []);

    useEffect(() => {
        void refresh();
    }, [refresh]);

    const openConfirmation = useCallback((nextConfirmation: Confirmation) => {
        setConfirmation(nextConfirmation);
    }, []);

    const confirmAction = async () => {
        if (!confirmation) {
            return;
        }
        setConfirmationBusy(true);
        try {
            await confirmation.action();
            setConfirmation(null);
        } finally {
            setConfirmationBusy(false);
        }
    };

    const handleStartOtp = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        setBusy(true);
        setError(null);
        setNotice(null);
        try {
            await startOtp(email.trim());
            setView('otp-sent');
            setOtp('');
            setNotice('If the address can receive messages, a one-time code has been sent.');
        } catch (startError) {
            setError(errorMessage(startError, 'The sign-in code could not be sent.'));
        } finally {
            setBusy(false);
        }
    };

    const handleResendOtp = async () => {
        setBusy(true);
        setError(null);
        setNotice(null);
        try {
            await startOtp(email.trim());
            setNotice('If the address can receive messages, a one-time code has been sent.');
        } catch (resendError) {
            setError(errorMessage(resendError, 'The sign-in code could not be sent.'));
        } finally {
            setBusy(false);
        }
    };

    const handleVerifyOtp = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        setBusy(true);
        setError(null);
        setNotice(null);
        try {
            const verified = await verifyOtp(email.trim(), otp.trim());
            setBootstrap(verified);
            setNeedsRecovery(false);
            setView('verified');
        } catch (verifyError) {
            setError(errorMessage(verifyError, 'The email or one-time code is invalid.'));
        } finally {
            setBusy(false);
        }
    };

    const prepareRegistration = async (isRecovery: boolean) => {
        if (!bootstrap) {
            return;
        }
        setBusy(true);
        setError(null);
        setNotice(null);
        try {
            const nextIdentity = await getOrCreateDeviceIdentity();
            const nextChallenge = await issueRegistrationChallenge(
                bootstrap.bootstrap_token,
                nextIdentity,
                label.trim(),
                isRecovery,
            );
            setIdentity(nextIdentity);
            setRecovery(nextChallenge.recovery);
            setChallenge(nextChallenge);
            setNeedsRecovery(false);
            setView('challenge');
        } catch (registrationError) {
            if (
                registrationError instanceof ApiError &&
                registrationError.status === 409 &&
                !isRecovery
            ) {
                setNeedsRecovery(true);
                setNotice(
                    'This account already has a trusted browser. Pair this browser from that device, or recover by email.',
                );
            } else {
                setError(
                    errorMessage(
                        registrationError,
                        'The browser enrollment request could not be created.',
                    ),
                );
            }
        } finally {
            setBusy(false);
        }
    };

    const requestEnrollment = () => {
        openConfirmation({
            title: 'Trust this browser?',
            description:
                'This browser will become a trusted device and receive an authenticated session after its key proof succeeds.',
            confirmLabel: 'Review enrollment',
            action: async () => prepareRegistration(false),
        });
    };

    const requestRecovery = () => {
        openConfirmation({
            title: 'Start account recovery?',
            description:
                'Recovery revokes every existing session and device. Other browsers will need to pair again after this browser is trusted.',
            confirmLabel: 'Start recovery',
            danger: true,
            action: async () => prepareRegistration(true),
        });
    };

    const completeEnrollmentAfterConfirmation = () => {
        if (!challenge || !identity) {
            return;
        }
        openConfirmation({
            title: recovery ? 'Finish account recovery?' : 'Finish browser enrollment?',
            description: recovery
                ? 'This final step will invalidate every other browser and session for this account.'
                : 'This final step will activate this browser as a trusted device.',
            confirmLabel: recovery ? 'Finish recovery' : 'Trust browser',
            danger: recovery,
            action: async () => {
                setBusy(true);
                setError(null);
                try {
                    const result = await completeRegistration(challenge, identity);
                    setNotice(result.warning ?? 'This browser is now trusted.');
                    setBootstrap(null);
                    setChallenge(null);
                    setIdentity(null);
                    await refresh();
                } catch (completionError) {
                    setError(errorMessage(completionError, 'The browser could not be trusted.'));
                } finally {
                    setBusy(false);
                }
            },
        });
    };

    const handleStartDeviceLogin = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        if (!ACCOUNT_ID_PATTERN.test(accountId.trim())) {
            setError('Enter the account ID from a previous signed-in session.');
            return;
        }
        setBusy(true);
        setError(null);
        setNotice(null);
        try {
            const nextIdentity = await loadDeviceIdentity();
            if (!nextIdentity) {
                throw new DeviceKeyMissingError('This browser does not have a trusted device key.');
            }
            const nextChallenge = await issueDeviceLoginChallenge(accountId.trim(), nextIdentity);
            setIdentity(nextIdentity);
            setLoginChallenge(nextChallenge);
            setView('login-challenge');
        } catch (loginError) {
            setError(errorMessage(loginError, 'This browser key could not start a sign-in.'));
        } finally {
            setBusy(false);
        }
    };

    const completeDeviceLoginFlow = async () => {
        if (!loginChallenge || !identity) {
            return;
        }
        setBusy(true);
        setError(null);
        try {
            const result = await completeDeviceLogin(loginChallenge, identity);
            setNotice(result.warning ?? 'Signed in with this browser key.');
            setLoginChallenge(null);
            setIdentity(null);
            await refresh();
        } catch (loginError) {
            setError(errorMessage(loginError, 'This browser key could not sign you in.'));
        } finally {
            setBusy(false);
        }
    };

    const handleRename = async (device: AuthenticatedDevice, event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const nextLabel = drafts[device.device_id]?.trim() ?? '';
        if (!nextLabel) {
            setError('Enter a browser label.');
            return;
        }
        setBusyDeviceId(device.device_id);
        setError(null);
        setNotice(null);
        try {
            const updated = await renameDevice(device.device_id, nextLabel);
            setDevices((current) =>
                current.map((item) => (item.device_id === updated.device_id ? updated : item)),
            );
            setDrafts((current) => ({ ...current, [updated.device_id]: updated.label }));
            setNotice('Browser label saved.');
        } catch (renameError) {
            setError(errorMessage(renameError, 'The browser label could not be saved.'));
        } finally {
            setBusyDeviceId(null);
        }
    };

    const handleRevoke = (device: AuthenticatedDevice) => {
        const isCurrent = device.device_id === session?.device_id;
        openConfirmation({
            title: isCurrent ? 'Revoke this browser?' : `Revoke ${device.label}?`,
            description: isCurrent
                ? 'This browser will be signed out immediately and its device key will no longer authenticate.'
                : 'This ends its sessions, closes its connections, and prevents it from approving or transferring files.',
            confirmLabel: 'Revoke browser',
            danger: true,
            action: async () => {
                setBusyDeviceId(device.device_id);
                setError(null);
                try {
                    await revokeDevice(device.device_id);
                    if (isCurrent) {
                        clearApiSession();
                        setSession(null);
                        setDevices([]);
                        setSessions([]);
                        setView('signed-out');
                        setNotice(
                            'This browser was revoked. Recover or pair it again to continue.',
                        );
                    } else {
                        setDevices((current) =>
                            current.filter((item) => item.device_id !== device.device_id),
                        );
                        setSessions((current) =>
                            current.filter((item) => item.device_id !== device.device_id),
                        );
                        setNotice('Browser revoked.');
                    }
                } catch (revokeError) {
                    setError(errorMessage(revokeError, 'The browser could not be revoked.'));
                } finally {
                    setBusyDeviceId(null);
                }
            },
        });
    };

    const handleLogout = async () => {
        setBusy(true);
        setError(null);
        try {
            await logout();
            clearApiSession();
            setSession(null);
            setDevices([]);
            setSessions([]);
            setView('signed-out');
            setNotice('Signed out of this browser.');
        } catch (logoutError) {
            setError(errorMessage(logoutError, 'This browser could not sign out.'));
        } finally {
            setBusy(false);
        }
    };

    const content =
        view === 'authenticated' && session ? (
            <AccountDashboard
                session={session}
                devices={devices}
                sessions={sessions}
                drafts={drafts}
                busyDeviceId={busyDeviceId}
                busy={busy}
                onRefresh={() => void refresh()}
                onDraftChange={(deviceId, value) =>
                    setDrafts((current) => ({ ...current, [deviceId]: value }))
                }
                onRename={(device, event) => void handleRename(device, event)}
                onRevoke={handleRevoke}
                onLogout={() => void handleLogout()}
            />
        ) : view === 'otp-sent' || view === 'signed-out' || view === 'error' ? (
            <OtpAccess
                view={view}
                email={email}
                otp={otp}
                label={label}
                busy={busy}
                accountId={accountId}
                onEmailChange={setEmail}
                onOtpChange={setOtp}
                onLabelChange={setLabel}
                onAccountIdChange={setAccountId}
                onStartOtp={(event) => void handleStartOtp(event)}
                onResendOtp={() => void handleResendOtp()}
                onVerifyOtp={(event) => void handleVerifyOtp(event)}
                onStartDeviceLogin={(event) => void handleStartDeviceLogin(event)}
            />
        ) : view === 'verified' ? (
            <section className="account-panel" aria-labelledby="verified-title">
                <div className="panel-heading">
                    <p className="section-kicker">Email verified</p>
                    <h2 id="verified-title">Register this browser</h2>
                    <p>
                        Your email is verified. The browser will generate a non-exportable key and
                        show its fingerprint before activation.
                    </p>
                </div>
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
                <div className="request-actions">
                    <button
                        className="button button-primary"
                        type="button"
                        onClick={requestEnrollment}
                        disabled={busy}
                    >
                        Review browser enrollment
                    </button>
                    {needsRecovery && (
                        <button
                            className="button button-danger"
                            type="button"
                            onClick={requestRecovery}
                            disabled={busy}
                        >
                            Recover account by email
                        </button>
                    )}
                </div>
                {needsRecovery && (
                    <p className="inline-message inline-message-warning" role="status">
                        Another trusted browser already exists. Pairing is safer when one is
                        available; recovery will invalidate the existing device set.
                    </p>
                )}
            </section>
        ) : view === 'challenge' && challenge && identity ? (
            <EnrollmentReview
                challenge={challenge}
                identity={identity}
                label={label}
                recovery={recovery}
                busy={busy}
                onConfirm={completeEnrollmentAfterConfirmation}
            />
        ) : view === 'login-challenge' && loginChallenge ? (
            <section className="account-panel" aria-labelledby="device-login-title">
                <div className="panel-heading">
                    <p className="section-kicker">Trusted browser key</p>
                    <h2 id="device-login-title">Confirm this browser key</h2>
                    <p>Sign the fresh challenge to resume the account session.</p>
                </div>
                <dl className="request-details">
                    <div>
                        <dt>Account ID</dt>
                        <dd>
                            <code>{loginChallenge.account_id}</code>
                        </dd>
                    </div>
                    <div>
                        <dt>Challenge</dt>
                        <dd>{formatExpiry(loginChallenge.expires_at)}</dd>
                    </div>
                </dl>
                <button
                    className="button button-primary"
                    type="button"
                    onClick={() => void completeDeviceLoginFlow()}
                    disabled={busy}
                >
                    {busy ? 'Signing in…' : 'Sign in with this key'}
                </button>
            </section>
        ) : view === 'checking' ? (
            <section className="account-panel empty-panel" aria-labelledby="account-checking-title">
                <p className="section-kicker">Account access</p>
                <h2 id="account-checking-title">Checking this browser session…</h2>
                <p className="empty-copy">Looking for an active trusted-device session.</p>
            </section>
        ) : (
            <section className="account-panel" aria-labelledby="account-error-title">
                <p className="section-kicker">Account access</p>
                <h2 id="account-error-title">Account details are unavailable</h2>
                <button
                    className="button button-secondary"
                    type="button"
                    onClick={() => void refresh()}
                >
                    Try again
                </button>
            </section>
        );

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
                    aria-live="polite"
                >
                    {notice}
                </p>
            )}
            {content}
            <ConfirmDialog
                confirmation={confirmation}
                busy={confirmationBusy}
                onCancel={() => setConfirmation(null)}
                onConfirm={() => void confirmAction()}
            />
        </>
    );
}

export default AccountConsole;
