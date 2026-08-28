import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { ApiError, getCurrentSession, type CurrentSession } from './pairingApi';
import {
    acceptTransfer,
    cancelTransfer,
    createTransferOffer,
    listOnlineDevices,
    listTransfers,
    rejectTransfer,
    type PresenceSocketMessage,
    type SignalingEnvelope,
    type TransferNotification,
    type TransferRequest,
} from './transferApi';
import { PresenceSocketClient, type PresenceClientStatus } from './presenceClient';
import { WebRtcTestSession, type WebRtcTestState } from './webrtcTestSession';

type TransferConsoleState = 'checking' | 'ready' | 'signed-out' | 'error';

const NOTIFICATION_STATUS: Record<TransferNotification['type'], TransferRequest['status']> = {
    transfer_offer: 'offered',
    transfer_accepted: 'accepted',
    transfer_rejected: 'rejected',
    transfer_cancelled: 'cancelled',
    transfer_expired: 'expired',
};

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
    if (error instanceof Error && error.message) {
        return error.message;
    }
    return fallback;
}

function transferFromNotification(message: TransferNotification): TransferRequest {
    return {
        v: message.v,
        transfer_id: message.transfer_id,
        sender_device_id: message.sender_device_id,
        recipient_device_id: message.recipient_device_id,
        created_at: message.created_at,
        expires_at: message.expires_at,
        status: NOTIFICATION_STATUS[message.type],
    };
}

function transferFromSignal(message: SignalingEnvelope): TransferRequest {
    return {
        v: message.v,
        transfer_id: message.transfer_id,
        sender_device_id: message.sender_device_id,
        recipient_device_id: message.recipient_device_id,
        status: 'accepted',
        created_at: new Date().toISOString(),
        expires_at: new Date(message.expires_at).toISOString(),
    };
}

function statusLabel(status: PresenceClientStatus): string {
    return {
        idle: 'Offline',
        connecting: 'Connecting',
        online: 'Online',
        reconnecting: 'Reconnecting',
        offline: 'Offline · retrying',
    }[status];
}

function transferStatusLabel(status: TransferRequest['status']): string {
    return status.charAt(0).toUpperCase() + status.slice(1);
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

function deviceName(
    deviceId: string,
    session: CurrentSession | null,
    devices: { device_id: string; label: string }[],
): string {
    if (session?.device_id === deviceId) {
        return 'This device';
    }
    return devices.find((device) => device.device_id === deviceId)?.label ?? 'Another device';
}

function TransferConsole() {
    const [session, setSession] = useState<CurrentSession | null>(null);
    const [devices, setDevices] = useState<{ device_id: string; label: string }[]>([]);
    const [transfers, setTransfers] = useState<TransferRequest[]>([]);
    const [state, setState] = useState<TransferConsoleState>('checking');
    const [socketStatus, setSocketStatus] = useState<PresenceClientStatus>('idle');
    const [connectionStates, setConnectionStates] = useState<Record<string, WebRtcTestState>>({});
    const [selectedDeviceId, setSelectedDeviceId] = useState('');
    const [busyTransferId, setBusyTransferId] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [notice, setNotice] = useState<string | null>(null);
    const sessionRef = useRef<CurrentSession | null>(null);
    const devicesRef = useRef(devices);
    const transfersRef = useRef<TransferRequest[]>([]);
    const socketRef = useRef<PresenceSocketClient | null>(null);
    const sessionsRef = useRef<Map<string, WebRtcTestSession>>(new Map());
    const queuedSignalsRef = useRef<Map<string, SignalingEnvelope[]>>(new Map());
    const socketMessageRef = useRef<(message: PresenceSocketMessage) => void>(() => undefined);

    useEffect(() => {
        devicesRef.current = devices;
    }, [devices]);

    useEffect(() => {
        sessionRef.current = session;
    }, [session]);

    const upsertTransfer = (next: TransferRequest) => {
        setTransfers((current) => {
            const index = current.findIndex(
                (transfer) => transfer.transfer_id === next.transfer_id,
            );
            const updated = [...current];
            if (index === -1) {
                updated.unshift(next);
            } else {
                updated[index] = next;
            }
            transfersRef.current = updated;
            return updated;
        });
    };

    const createTestSession = (
        transfer: TransferRequest,
        role: 'sender' | 'recipient',
    ): WebRtcTestSession | null => {
        const existing = sessionsRef.current.get(transfer.transfer_id);
        if (existing) {
            return existing;
        }
        const socket = socketRef.current;
        if (!socket) {
            setError('The presence socket is not ready yet. Try again in a moment.');
            return null;
        }
        const testSession = new WebRtcTestSession({
            transfer,
            role,
            sendSignal: (message) => socket.send(message),
            onStateChange: (nextState) => {
                setConnectionStates((current) => ({
                    ...current,
                    [transfer.transfer_id]: nextState,
                }));
            },
        });
        sessionsRef.current.set(transfer.transfer_id, testSession);
        setConnectionStates((current) => ({
            ...current,
            [transfer.transfer_id]: testSession.state,
        }));
        return testSession;
    };

    const handleSignalingMessage = async (message: SignalingEnvelope): Promise<void> => {
        const currentSession = sessionRef.current;
        if (
            !currentSession ||
            ![message.sender_device_id, message.recipient_device_id].includes(
                currentSession.device_id,
            )
        ) {
            return;
        }
        let testSession = sessionsRef.current.get(message.transfer_id) ?? null;
        if (!testSession) {
            if (
                message.type !== 'sdp_offer' ||
                currentSession.device_id !== message.recipient_device_id
            ) {
                const queued = queuedSignalsRef.current.get(message.transfer_id) ?? [];
                queued.push(message);
                queuedSignalsRef.current.set(message.transfer_id, queued);
                return;
            }
            const transfer =
                transfersRef.current.find((item) => item.transfer_id === message.transfer_id) ??
                transferFromSignal(message);
            upsertTransfer(transfer);
            testSession = createTestSession(transfer, 'recipient');
            if (!testSession) {
                return;
            }
            const queued = queuedSignalsRef.current.get(message.transfer_id) ?? [];
            queuedSignalsRef.current.delete(message.transfer_id);
            for (const queuedMessage of queued) {
                await testSession.handleSignal(queuedMessage);
            }
        }
        await testSession.handleSignal(message);
    };

    socketMessageRef.current = (message) => {
        if (message.type === 'presence') {
            setDevices(message.devices);
            devicesRef.current = message.devices;
            if (!selectedDeviceId && message.devices.length > 0) {
                const firstOther = message.devices.find(
                    (device) => device.device_id !== sessionRef.current?.device_id,
                );
                if (firstOther) {
                    setSelectedDeviceId(firstOther.device_id);
                }
            }
            return;
        }
        if (
            message.type === 'transfer_offer' ||
            message.type === 'transfer_accepted' ||
            message.type === 'transfer_rejected' ||
            message.type === 'transfer_cancelled' ||
            message.type === 'transfer_expired'
        ) {
            upsertTransfer(transferFromNotification(message));
            return;
        }
        if (
            message.type === 'sdp_offer' ||
            message.type === 'sdp_answer' ||
            message.type === 'ice_candidate'
        ) {
            void handleSignalingMessage(message).catch((signalError: unknown) => {
                setError(
                    errorMessage(signalError, 'The browser connection could not be negotiated.'),
                );
            });
        }
    };

    const refresh = useCallback(async (): Promise<void> => {
        try {
            const current = await getCurrentSession();
            sessionRef.current = current;
            setSession(current);
            const [online, existing] = await Promise.all([listOnlineDevices(), listTransfers()]);
            setDevices(online);
            devicesRef.current = online;
            setSelectedDeviceId(
                (selected) =>
                    selected ||
                    online.find((device) => device.device_id !== current.device_id)?.device_id ||
                    '',
            );
            transfersRef.current = existing;
            setTransfers(existing);
            setState('ready');
            setError(null);
        } catch (refreshError) {
            if (refreshError instanceof ApiError && refreshError.status === 401) {
                sessionRef.current = null;
                setSession(null);
                setDevices([]);
                setTransfers([]);
                transfersRef.current = [];
                setState('signed-out');
                setError(null);
                return;
            }
            setState('error');
            setError(errorMessage(refreshError, 'Transfer devices could not be loaded.'));
        }
    }, []);

    useEffect(() => {
        let mounted = true;
        const testSessions = sessionsRef.current;
        const queuedSignals = queuedSignalsRef.current;
        const initialize = async () => {
            await refresh();
            if (!mounted || !sessionRef.current) {
                return;
            }
            const socket = new PresenceSocketClient({
                onMessage: (message) => socketMessageRef.current(message),
                onStatusChange: (nextStatus) => setSocketStatus(nextStatus),
                onError: (socketError) => {
                    if (mounted) {
                        setError(
                            errorMessage(socketError, 'The presence socket could not connect.'),
                        );
                    }
                },
            });
            socketRef.current = socket;
            try {
                await socket.connect();
            } catch {
                // The client keeps retrying while the transfer view is mounted.
            }
        };
        void initialize();
        return () => {
            mounted = false;
            socketRef.current?.stop();
            socketRef.current = null;
            for (const testSession of testSessions.values()) {
                testSession.close();
            }
            testSessions.clear();
            queuedSignals.clear();
        };
    }, [refresh]);

    const otherDevices = useMemo(
        () => devices.filter((device) => device.device_id !== session?.device_id),
        [devices, session?.device_id],
    );
    const incomingOffers = useMemo(
        () =>
            transfers.filter(
                (transfer) =>
                    transfer.recipient_device_id === session?.device_id &&
                    transfer.status === 'offered',
            ),
        [session?.device_id, transfers],
    );

    const handleCreateOffer = async () => {
        if (!selectedDeviceId) {
            setError('Choose an online device first.');
            return;
        }
        setBusyTransferId('new');
        setError(null);
        setNotice(null);
        try {
            const created = await createTransferOffer(selectedDeviceId);
            upsertTransfer(created);
            setNotice(
                'Generic transfer offer sent. The other device must accept before negotiation starts.',
            );
        } catch (createError) {
            setError(errorMessage(createError, 'The transfer offer could not be created.'));
        } finally {
            setBusyTransferId(null);
        }
    };

    const handleAccept = async (transfer: TransferRequest) => {
        setBusyTransferId(transfer.transfer_id);
        setError(null);
        setNotice(null);
        try {
            const accepted = await acceptTransfer(transfer.transfer_id);
            upsertTransfer(accepted);
            const testSession = createTestSession(accepted, 'recipient');
            await testSession?.start();
            setNotice('Offer accepted. The sender can now start the WebRTC connection test.');
        } catch (acceptError) {
            setError(errorMessage(acceptError, 'The transfer offer could not be accepted.'));
        } finally {
            setBusyTransferId(null);
        }
    };

    const handleReject = async (transfer: TransferRequest) => {
        setBusyTransferId(transfer.transfer_id);
        setError(null);
        setNotice(null);
        try {
            upsertTransfer(await rejectTransfer(transfer.transfer_id));
            setNotice('The generic transfer offer was rejected.');
        } catch (rejectError) {
            setError(errorMessage(rejectError, 'The transfer offer could not be rejected.'));
        } finally {
            setBusyTransferId(null);
        }
    };

    const handleCancel = async (transfer: TransferRequest) => {
        setBusyTransferId(transfer.transfer_id);
        setError(null);
        setNotice(null);
        try {
            upsertTransfer(await cancelTransfer(transfer.transfer_id));
            sessionsRef.current.get(transfer.transfer_id)?.close();
            setNotice('The transfer was cancelled.');
        } catch (cancelError) {
            setError(errorMessage(cancelError, 'The transfer could not be cancelled.'));
        } finally {
            setBusyTransferId(null);
        }
    };

    const handleTestConnection = async (transfer: TransferRequest) => {
        if (!session) {
            return;
        }
        setError(null);
        const role = transfer.sender_device_id === session.device_id ? 'sender' : 'recipient';
        const testSession = createTestSession(transfer, role);
        if (!testSession) {
            return;
        }
        try {
            await testSession.start();
            setNotice('WebRTC negotiation started. No file data is sent by this test.');
        } catch (testError) {
            setError(errorMessage(testError, 'The WebRTC connection test could not start.'));
        }
    };

    if (state === 'checking') {
        return (
            <section
                className="pairing-panel empty-panel transfer-panel"
                aria-labelledby="transfer-title"
            >
                <p className="section-kicker">Secure transfer</p>
                <h2 id="transfer-title">Checking your trusted session…</h2>
                <p className="empty-copy">Looking for online devices on this account.</p>
            </section>
        );
    }

    if (state === 'signed-out') {
        return (
            <section
                className="pairing-panel empty-panel transfer-panel"
                aria-labelledby="transfer-title"
            >
                <p className="section-kicker">Secure transfer</p>
                <h2 id="transfer-title">Sign in on this browser first</h2>
                <p className="empty-copy">
                    A current trusted session is required to see devices and create offers.
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
        <section className="pairing-panel transfer-panel" aria-labelledby="transfer-title">
            <div className="panel-heading panel-heading-row">
                <div>
                    <p className="section-kicker">Secure transfer</p>
                    <h2 id="transfer-title">Connect two trusted devices</h2>
                    <p>
                        Offers contain no file details. Accept a request before the browser
                        connection test begins.
                    </p>
                </div>
                <span className={`request-state request-state-${socketStatus}`} role="status">
                    <span className="status-dot" aria-hidden="true" />
                    {statusLabel(socketStatus)}
                </span>
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
            <div className="transfer-create">
                <div>
                    <p className="request-label">Start an offer</p>
                    <strong>Choose an online device</strong>
                </div>
                <select
                    aria-label="Recipient device"
                    value={selectedDeviceId}
                    onChange={(event) => setSelectedDeviceId(event.target.value)}
                    disabled={otherDevices.length === 0 || busyTransferId === 'new'}
                >
                    <option value="">Select a device</option>
                    {otherDevices.map((device) => (
                        <option key={device.device_id} value={device.device_id}>
                            {device.label}
                        </option>
                    ))}
                </select>
                <button
                    className="button button-primary"
                    type="button"
                    onClick={() => void handleCreateOffer()}
                    disabled={!selectedDeviceId || busyTransferId === 'new'}
                >
                    {busyTransferId === 'new' ? 'Sending…' : 'Send generic offer'}
                </button>
            </div>
            {otherDevices.length === 0 && (
                <p className="inline-message inline-message-neutral" role="status">
                    No other trusted devices are online right now.
                </p>
            )}
            {incomingOffers.length > 0 && (
                <div className="transfer-group" aria-labelledby="incoming-offers-title">
                    <div className="transfer-group-heading">
                        <div>
                            <p className="request-label">Incoming</p>
                            <h3 id="incoming-offers-title">Generic transfer offers</h3>
                        </div>
                        <span className="request-expiry">{incomingOffers.length}</span>
                    </div>
                    <div className="transfer-list">
                        {incomingOffers.map((transfer) => {
                            const busy = busyTransferId === transfer.transfer_id;
                            return (
                                <article className="transfer-card" key={transfer.transfer_id}>
                                    <div className="trusted-request-heading">
                                        <div>
                                            <span className="request-label">
                                                From{' '}
                                                {deviceName(
                                                    transfer.sender_device_id,
                                                    session,
                                                    devices,
                                                )}
                                            </span>
                                            <h3>Generic transfer request</h3>
                                        </div>
                                        <span className="request-expiry">
                                            Expires {formatDate(transfer.expires_at)}
                                        </span>
                                    </div>
                                    <p className="transfer-copy">
                                        No file name, type, size, or message is visible until you
                                        accept and establish a secure channel.
                                    </p>
                                    <div className="request-actions">
                                        <button
                                            className="button button-primary"
                                            type="button"
                                            onClick={() => void handleAccept(transfer)}
                                            disabled={busy}
                                        >
                                            {busy ? 'Working…' : 'Accept offer'}
                                        </button>
                                        <button
                                            className="button button-danger"
                                            type="button"
                                            onClick={() => void handleReject(transfer)}
                                            disabled={busy}
                                        >
                                            Reject
                                        </button>
                                    </div>
                                </article>
                            );
                        })}
                    </div>
                </div>
            )}
            <div className="transfer-group" aria-labelledby="activity-title">
                <div className="transfer-group-heading">
                    <div>
                        <p className="request-label">Activity</p>
                        <h3 id="activity-title">Transfer control</h3>
                    </div>
                    <button
                        className="button button-small"
                        type="button"
                        onClick={() => void refresh()}
                    >
                        Refresh
                    </button>
                </div>
                {transfers.length === 0 ? (
                    <div className="empty-state">
                        <span className="empty-glyph" aria-hidden="true">
                            ⌁
                        </span>
                        <strong>No transfer offers yet</strong>
                        <p>Choose an online device to create a generic offer.</p>
                    </div>
                ) : (
                    <div className="transfer-list">
                        {transfers.map((transfer) => {
                            const busy = busyTransferId === transfer.transfer_id;
                            const connectionState = connectionStates[transfer.transfer_id];
                            const isParticipant =
                                transfer.sender_device_id === session?.device_id ||
                                transfer.recipient_device_id === session?.device_id;
                            const canTest =
                                isParticipant &&
                                ['accepted', 'negotiating', 'connected'].includes(transfer.status);
                            const canCancel =
                                isParticipant &&
                                [
                                    'offered',
                                    'accepted',
                                    'negotiating',
                                    'connected',
                                    'transferring',
                                ].includes(transfer.status);
                            return (
                                <article className="transfer-card" key={transfer.transfer_id}>
                                    <div className="trusted-request-heading">
                                        <div>
                                            <span className="request-label">
                                                {transferStatusLabel(transfer.status)}
                                            </span>
                                            <h3>
                                                {deviceName(
                                                    transfer.sender_device_id,
                                                    session,
                                                    devices,
                                                )}{' '}
                                                →{' '}
                                                {deviceName(
                                                    transfer.recipient_device_id,
                                                    session,
                                                    devices,
                                                )}
                                            </h3>
                                        </div>
                                        {connectionState && (
                                            <span className="request-expiry">
                                                WebRTC {connectionState}
                                            </span>
                                        )}
                                    </div>
                                    <p className="transfer-copy">
                                        Generic control-plane offer created{' '}
                                        {formatDate(transfer.created_at)}. File metadata is not part
                                        of this request.
                                    </p>
                                    <div className="request-actions">
                                        {canTest && (
                                            <button
                                                className="button button-primary"
                                                type="button"
                                                onClick={() => void handleTestConnection(transfer)}
                                                disabled={busy || connectionState === 'connected'}
                                            >
                                                {connectionState === 'connected'
                                                    ? 'Channel connected'
                                                    : 'Test data channel'}
                                            </button>
                                        )}
                                        {canCancel && (
                                            <button
                                                className="button button-danger"
                                                type="button"
                                                onClick={() => void handleCancel(transfer)}
                                                disabled={busy}
                                            >
                                                Cancel
                                            </button>
                                        )}
                                    </div>
                                </article>
                            );
                        })}
                    </div>
                )}
            </div>
        </section>
    );
}

export default TransferConsole;
