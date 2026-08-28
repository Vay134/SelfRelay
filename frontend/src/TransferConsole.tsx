import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { ApiError, getCurrentSession, type CurrentSession } from './pairingApi';
import { DeviceKeyMissingError, loadDeviceIdentity, type DeviceIdentity } from './deviceIdentity';
import {
    acceptTransfer,
    cancelTransfer,
    createTransferOffer,
    getTransferPeerDeviceKey,
    getTransferTurnCredentials,
    listOnlineDevices,
    listTransfers,
    rejectTransfer,
    type PresenceSocketMessage,
    type SignalingEnvelope,
    type TransferNotification,
    type TransferRequest,
} from './transferApi';
import {
    FileTransferEngine,
    MAX_TRANSFER_BYTES,
    type FileTransferState,
    type ReceivedFile,
    type TransferProgress,
    type TransferReceipt,
} from './fileTransfer';
import { PresenceSocketClient, type PresenceClientStatus } from './presenceClient';
import { decodeBase64Url, importP256Spki, type DerivedHandshakeMaterial } from './transferProtocol';
import { rtcConfigurationFromTurnCredentials } from './rtcConfiguration';
import {
    WebRtcTestSession,
    type WebRtcRelayStatus,
    type WebRtcTestState,
} from './webrtcTestSession';

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

type TransferRun = {
    state: FileTransferState;
    progress: TransferProgress | null;
    fileName?: string;
    fileSize?: number;
    receivedFile?: ReceivedFile;
    receipt?: TransferReceipt;
    error?: string;
    relayStatus?: WebRtcRelayStatus;
};

type TransferSessionContext = {
    transfer: TransferRequest;
    role: 'sender' | 'recipient';
    identity: DeviceIdentity;
    peerSigningPublicKey: CryptoKey;
    session?: WebRtcTestSession;
    channel?: RTCDataChannel;
    material?: DerivedHandshakeMaterial;
    engine?: FileTransferEngine;
    enginePromise?: Promise<FileTransferEngine>;
};

function formatBytes(value: number): string {
    if (value === 0) {
        return '0 B';
    }
    const units = ['B', 'KB', 'MB', 'GB'];
    const unitIndex = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)));
    const amount = value / 1024 ** unitIndex;
    return `${amount >= 10 || unitIndex === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unitIndex]}`;
}

function fileTransferStateLabel(state: FileTransferState): string {
    return {
        idle: 'Choose a file',
        confirming: 'Confirming secure channel',
        ready: 'Secure channel ready',
        sending: 'Sending file',
        receiving: 'Receiving file',
        completed: 'Verified',
        cancelled: 'Cancelled',
        failed: 'Transfer failed',
        closed: 'Closed',
    }[state];
}

function transferProgressPercent(
    progress: TransferProgress | null,
    state?: FileTransferState,
): number {
    if (!progress || progress.totalBytes <= 0) {
        return state === 'completed' ? 100 : 0;
    }
    return Math.min(100, Math.round((progress.bytesTransferred / progress.totalBytes) * 100));
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
    const [transferRuns, setTransferRuns] = useState<Record<string, TransferRun>>({});
    const sessionRef = useRef<CurrentSession | null>(null);
    const devicesRef = useRef(devices);
    const transfersRef = useRef<TransferRequest[]>([]);
    const transferRunsRef = useRef<Record<string, TransferRun>>({});
    const localIdentityPromiseRef = useRef<Promise<DeviceIdentity> | null>(null);
    const socketRef = useRef<PresenceSocketClient | null>(null);
    const sessionsRef = useRef<Map<string, WebRtcTestSession>>(new Map());
    const sessionContextsRef = useRef<Map<string, TransferSessionContext>>(new Map());
    const sessionCreationRef = useRef<Map<string, Promise<WebRtcTestSession | null>>>(new Map());
    const fileSelectionsRef = useRef<Map<string, File>>(new Map());
    const sendStartedRef = useRef<Set<string>>(new Set());
    const cancelledTransfersRef = useRef<Set<string>>(new Set());
    const cleaningTransfersRef = useRef<Set<string>>(new Set());
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

    const updateTransferRun = (transferId: string, patch: Partial<TransferRun>): void => {
        setTransferRuns((current) => {
            const previous = current[transferId];
            const next = {
                ...current,
                [transferId]: {
                    ...previous,
                    state: previous?.state ?? ('idle' as FileTransferState),
                    progress: previous?.progress ?? null,
                    ...patch,
                },
            };
            transferRunsRef.current = next;
            return next;
        });
    };

    const markSessionFailed = (transferId: string, error: unknown, fallback: string): void => {
        const message = errorMessage(error, fallback);
        setConnectionStates((currentStates) => ({
            ...currentStates,
            [transferId]: 'failed',
        }));
        updateTransferRun(transferId, {
            state: 'failed',
            error: message,
        });
        setError(message);
    };

    const loadLocalIdentity = async (): Promise<DeviceIdentity> => {
        if (!localIdentityPromiseRef.current) {
            const pending = (async () => {
                const identity = await loadDeviceIdentity();
                if (!identity) {
                    throw new DeviceKeyMissingError(
                        'This trusted browser no longer has its device key. Restore site data before transferring.',
                    );
                }
                const current = sessionRef.current;
                if (current && identity.deviceId !== current.device_id) {
                    throw new DeviceKeyMissingError(
                        'The saved device key belongs to a different trusted device.',
                    );
                }
                return identity;
            })();
            localIdentityPromiseRef.current = pending;
            void pending.catch(() => {
                if (localIdentityPromiseRef.current === pending) {
                    localIdentityPromiseRef.current = null;
                }
            });
        }
        return localIdentityPromiseRef.current;
    };

    const startFileTransfer = async (
        transferId: string,
        file: File,
        engine: FileTransferEngine,
    ): Promise<void> => {
        if (sendStartedRef.current.has(transferId)) {
            return;
        }
        sendStartedRef.current.add(transferId);
        try {
            const receipt = await engine.sendFile(file, file.name);
            updateTransferRun(transferId, {
                state: 'completed',
                receipt,
                progress: {
                    bytesTransferred: file.size,
                    totalBytes: file.size,
                    chunkCount: transferRunsRef.current[transferId]?.progress?.chunkCount ?? 0,
                },
            });
        } catch (transferError) {
            updateTransferRun(transferId, {
                state: engine.state === 'cancelled' ? 'cancelled' : 'failed',
                error: errorMessage(transferError, 'The file could not be sent.'),
            });
            setError(errorMessage(transferError, 'The file could not be sent.'));
        }
    };

    const createFileEngine = async (transferId: string): Promise<void> => {
        const context = sessionContextsRef.current.get(transferId);
        if (
            !context ||
            context.engine ||
            context.enginePromise ||
            !context.channel ||
            !context.material
        ) {
            return;
        }
        const creation = (async (): Promise<FileTransferEngine> => {
            const engine = new FileTransferEngine({
                channel: context.channel as RTCDataChannel,
                transferId,
                role: context.role,
                material: context.material as DerivedHandshakeMaterial,
                signingKey: context.role === 'sender' ? context.identity.privateKey : undefined,
                senderSigningPublicKey:
                    context.role === 'recipient' ? context.peerSigningPublicKey : undefined,
                accepted: context.role === 'recipient',
                inboundDeviceId:
                    context.role === 'recipient' ? context.identity.deviceId : undefined,
                onProgress: (progress) => {
                    updateTransferRun(transferId, { progress });
                },
                onStateChange: (nextState) => {
                    if (!cleaningTransfersRef.current.has(transferId)) {
                        updateTransferRun(transferId, { state: nextState });
                    }
                },
                onManifest: (manifest) => {
                    updateTransferRun(transferId, {
                        fileName: manifest.file_name,
                        fileSize: manifest.byte_count,
                        progress: {
                            bytesTransferred: 0,
                            totalBytes: manifest.byte_count,
                            chunkCount: 0,
                        },
                    });
                },
                onReceived: (receivedFile) => {
                    updateTransferRun(transferId, {
                        state: 'completed',
                        fileName: receivedFile.fileName,
                        fileSize: receivedFile.byteCount,
                        receivedFile,
                        progress: {
                            bytesTransferred: receivedFile.byteCount,
                            totalBytes: receivedFile.byteCount,
                            chunkCount:
                                transferRunsRef.current[transferId]?.progress?.chunkCount ?? 0,
                        },
                    });
                },
                onReceipt: (receipt) => {
                    updateTransferRun(transferId, { receipt, state: 'completed' });
                },
                onError: (transferError) => {
                    if (!cleaningTransfersRef.current.has(transferId)) {
                        updateTransferRun(transferId, {
                            state: 'failed',
                            error: transferError.message,
                        });
                        setError(transferError.message);
                    }
                },
            });
            context.engine = engine;
            const selectedFile = fileSelectionsRef.current.get(transferId);
            if (context.role === 'sender' && selectedFile) {
                void startFileTransfer(transferId, selectedFile, engine);
            }
            return engine;
        })();
        context.enginePromise = creation;
        try {
            await creation;
        } catch (engineError) {
            updateTransferRun(transferId, {
                state: 'failed',
                error: errorMessage(engineError, 'The secure transfer could not start.'),
            });
            setError(errorMessage(engineError, 'The secure transfer could not start.'));
        } finally {
            if (context.enginePromise === creation) {
                context.enginePromise = undefined;
            }
        }
    };

    const createTestSession = async (
        transfer: TransferRequest,
        role: 'sender' | 'recipient',
    ): Promise<WebRtcTestSession | null> => {
        const existing = sessionsRef.current.get(transfer.transfer_id);
        if (existing) {
            return existing;
        }
        const pending = sessionCreationRef.current.get(transfer.transfer_id);
        if (pending) {
            return pending;
        }
        const creation = (async (): Promise<WebRtcTestSession | null> => {
            if (cancelledTransfersRef.current.has(transfer.transfer_id)) {
                return null;
            }
            const socket = socketRef.current;
            if (!socket) {
                throw new Error('The presence socket is not ready yet. Try again in a moment.');
            }
            const current = sessionRef.current;
            if (!current) {
                throw new Error('The trusted session is no longer available.');
            }
            const identity = await loadLocalIdentity();
            const peer = await getTransferPeerDeviceKey(transfer.transfer_id);
            const expectedPeerDeviceId =
                role === 'sender' ? transfer.recipient_device_id : transfer.sender_device_id;
            if (peer.device_id !== expectedPeerDeviceId) {
                throw new Error('The transfer peer identity does not match this offer.');
            }
            const peerSigningPublicKey = await importP256Spki(
                decodeBase64Url(peer.public_key_spki, 1024),
                'signing',
            );
            const turnCredentials = await getTransferTurnCredentials(transfer.transfer_id);
            if (cancelledTransfersRef.current.has(transfer.transfer_id)) {
                return null;
            }
            const context: TransferSessionContext = {
                transfer,
                role,
                identity,
                peerSigningPublicKey,
            };
            sessionContextsRef.current.set(transfer.transfer_id, context);
            try {
                const testSession = new WebRtcTestSession({
                    transfer,
                    role,
                    sendSignal: (message) => socket.send(message),
                    rtcConfiguration: rtcConfigurationFromTurnCredentials(turnCredentials),
                    signingKey: identity.privateKey,
                    peerSigningPublicKey,
                    accountEpoch: current.account_device_epoch,
                    onStateChange: (nextState) => {
                        setConnectionStates((currentStates) => ({
                            ...currentStates,
                            [transfer.transfer_id]: nextState,
                        }));
                        if (nextState === 'failed' && !context.engine) {
                            updateTransferRun(transfer.transfer_id, {
                                state: 'failed',
                                error: 'The browser connection could not be negotiated.',
                            });
                        }
                    },
                    onRelayStatusChange: (relayStatus) => {
                        updateTransferRun(transfer.transfer_id, { relayStatus });
                    },
                    onDataChannel: (channel) => {
                        context.channel = channel;
                        void createFileEngine(transfer.transfer_id);
                    },
                    onHandshake: (material) => {
                        context.material = material;
                        void createFileEngine(transfer.transfer_id);
                    },
                });
                context.session = testSession;
                sessionsRef.current.set(transfer.transfer_id, testSession);
                setConnectionStates((currentStates) => ({
                    ...currentStates,
                    [transfer.transfer_id]: testSession.state,
                }));
                return testSession;
            } catch (sessionError) {
                sessionContextsRef.current.delete(transfer.transfer_id);
                throw sessionError;
            }
        })();
        sessionCreationRef.current.set(transfer.transfer_id, creation);
        try {
            return await creation;
        } finally {
            if (sessionCreationRef.current.get(transfer.transfer_id) === creation) {
                sessionCreationRef.current.delete(transfer.transfer_id);
            }
        }
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
            const canCreateRecipientSession =
                (message.type === 'handshake_offer' || message.type === 'sdp_offer') &&
                currentSession.device_id === message.recipient_device_id;
            if (!canCreateRecipientSession) {
                const queued = queuedSignalsRef.current.get(message.transfer_id) ?? [];
                queued.push(message);
                queuedSignalsRef.current.set(message.transfer_id, queued);
                return;
            }
            const transfer =
                transfersRef.current.find((item) => item.transfer_id === message.transfer_id) ??
                transferFromSignal(message);
            upsertTransfer(transfer);
            testSession = await createTestSession(transfer, 'recipient');
            if (!testSession) {
                return;
            }
            const queued = queuedSignalsRef.current.get(message.transfer_id) ?? [];
            queuedSignalsRef.current.delete(message.transfer_id);
            const queuedMessages =
                message.type === 'handshake_offer' ? [message, ...queued] : [...queued, message];
            for (const queuedMessage of queuedMessages) {
                await testSession.handleSignal(queuedMessage);
            }
            return;
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
            message.type === 'ice_candidate' ||
            message.type === 'handshake_offer' ||
            message.type === 'handshake_answer'
        ) {
            void handleSignalingMessage(message).catch((signalError: unknown) => {
                markSessionFailed(
                    message.transfer_id,
                    signalError,
                    'The browser connection could not be negotiated.',
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
        const sessionContexts = sessionContextsRef.current;
        const fileSelections = fileSelectionsRef.current;
        const sendStarted = sendStartedRef.current;
        const cancelledTransfers = cancelledTransfersRef.current;
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
            for (const engine of sessionContexts.values()) {
                engine.engine?.dispose();
            }
            sessionContexts.clear();
            for (const testSession of testSessions.values()) {
                testSession.close();
            }
            testSessions.clear();
            queuedSignals.clear();
            fileSelections.clear();
            sendStarted.clear();
            cancelledTransfers.clear();
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

    const cleanupTransferRuntime = async (transferId: string): Promise<void> => {
        cancelledTransfersRef.current.add(transferId);
        cleaningTransfersRef.current.add(transferId);
        try {
            const context = sessionContextsRef.current.get(transferId);
            const engine = context?.engine;
            if (engine && !['completed', 'cancelled', 'failed', 'closed'].includes(engine.state)) {
                try {
                    await engine.reject('cancelled');
                } catch {
                    // Closing the channel below still removes all local transfer state.
                }
            }
            const receivedFile = transferRunsRef.current[transferId]?.receivedFile;
            if (receivedFile?.downloadUrl && typeof URL.revokeObjectURL === 'function') {
                URL.revokeObjectURL(receivedFile.downloadUrl);
            }
            engine?.dispose();
            context?.session?.close();
        } finally {
            sessionContextsRef.current.delete(transferId);
            sessionsRef.current.delete(transferId);
            sessionCreationRef.current.delete(transferId);
            queuedSignalsRef.current.delete(transferId);
            fileSelectionsRef.current.delete(transferId);
            sendStartedRef.current.delete(transferId);
            cleaningTransfersRef.current.delete(transferId);
            updateTransferRun(transferId, {
                state: 'cancelled',
                receivedFile: undefined,
                error: undefined,
            });
        }
    };

    const startSenderSession = async (transfer: TransferRequest): Promise<void> => {
        try {
            const testSession = await createTestSession(transfer, 'sender');
            if (!testSession) {
                throw new Error('The authenticated transfer session could not be created.');
            }
            await testSession.start();
        } catch (sessionError) {
            markSessionFailed(
                transfer.transfer_id,
                sessionError,
                'The secure transfer could not start.',
            );
        }
    };

    const handleFileSelected = (transfer: TransferRequest, file: File | undefined): void => {
        if (!file) {
            return;
        }
        if (file.size > MAX_TRANSFER_BYTES) {
            fileSelectionsRef.current.delete(transfer.transfer_id);
            updateTransferRun(transfer.transfer_id, {
                state: 'failed',
                fileName: file.name,
                fileSize: file.size,
                progress: null,
                error: `This file is larger than the ${formatBytes(MAX_TRANSFER_BYTES)} limit.`,
            });
            setError(`Choose a file no larger than ${formatBytes(MAX_TRANSFER_BYTES)}.`);
            return;
        }
        fileSelectionsRef.current.set(transfer.transfer_id, file);
        updateTransferRun(transfer.transfer_id, {
            state: 'confirming',
            fileName: file.name,
            fileSize: file.size,
            progress: {
                bytesTransferred: 0,
                totalBytes: file.size,
                chunkCount: 0,
            },
            error: undefined,
        });
        setError(null);
        setNotice('File selected. Establishing the authenticated secure channel…');
        void startSenderSession(transfer);
    };

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
            updateTransferRun(accepted.transfer_id, { state: 'confirming', error: undefined });
            const testSession = await createTestSession(accepted, 'recipient');
            if (!testSession) {
                throw new Error('The authenticated transfer session could not be created.');
            }
            await testSession?.start();
            setNotice('Offer accepted. Waiting for the sender to choose a file.');
        } catch (acceptError) {
            markSessionFailed(
                transfer.transfer_id,
                acceptError,
                'The transfer offer could not be accepted.',
            );
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
            cancelledTransfersRef.current.add(transfer.transfer_id);
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
        let cancelErrorMessage: string | null = null;
        try {
            upsertTransfer(await cancelTransfer(transfer.transfer_id));
        } catch (cancelError) {
            cancelErrorMessage = errorMessage(cancelError, 'The transfer could not be cancelled.');
        } finally {
            await cleanupTransferRuntime(transfer.transfer_id);
            if (cancelErrorMessage) {
                setError(cancelErrorMessage);
            } else {
                setNotice('The transfer was cancelled.');
            }
            setBusyTransferId(null);
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
                        Offers contain no file details. Accept a request, then send a file through
                        the authenticated browser channel.
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
                            const run = transferRuns[transfer.transfer_id];
                            const isSender = transfer.sender_device_id === session?.device_id;
                            const runHasEnded =
                                run !== undefined &&
                                ['completed', 'cancelled', 'closed'].includes(run.state);
                            const canChooseFile =
                                isSender &&
                                transfer.status === 'accepted' &&
                                !busy &&
                                (!run ||
                                    (run.state === 'failed' &&
                                        !sessionsRef.current.has(transfer.transfer_id)));
                            const canCancel =
                                isParticipant &&
                                [
                                    'offered',
                                    'accepted',
                                    'negotiating',
                                    'connected',
                                    'transferring',
                                ].includes(transfer.status) &&
                                !runHasEnded;
                            const progress = run?.progress ?? null;
                            const progressPercent = transferProgressPercent(progress, run?.state);
                            const progressMax = Math.max(1, progress?.totalBytes ?? 1);
                            const progressValue = Math.min(
                                progressMax,
                                progress?.bytesTransferred ?? (run?.state === 'completed' ? 1 : 0),
                            );
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
                                                Browser channel {connectionState}
                                            </span>
                                        )}
                                    </div>
                                    {!run && transfer.status === 'accepted' && isSender && (
                                        <p className="transfer-copy">
                                            Accepted. Choose a file to start the authenticated
                                            transfer; its name and size stay private until then.
                                        </p>
                                    )}
                                    {!run && transfer.status === 'accepted' && !isSender && (
                                        <p className="transfer-copy">
                                            Accepted. Waiting for the sender to choose a file and
                                            open the secure channel.
                                        </p>
                                    )}
                                    {(!run || transfer.status !== 'accepted') && (
                                        <p className="transfer-copy">
                                            Generic control-plane offer created{' '}
                                            {formatDate(transfer.created_at)}. File metadata is not
                                            part of this request.
                                        </p>
                                    )}
                                    {run?.fileName && (
                                        <p className="transfer-copy">
                                            <strong>{run.fileName}</strong>
                                            {run.fileSize !== undefined &&
                                                ` · ${formatBytes(run.fileSize)}`}
                                        </p>
                                    )}
                                    {run && run.state !== 'idle' && (
                                        <div
                                            className="transfer-progress"
                                            role="status"
                                            aria-live="polite"
                                        >
                                            <div className="trusted-request-heading">
                                                <span className="request-label">
                                                    {fileTransferStateLabel(run.state)}
                                                </span>
                                                <span className="request-expiry">
                                                    {progressPercent}%
                                                    {progress &&
                                                        ` · ${formatBytes(progress.bytesTransferred)} of ${formatBytes(progress.totalBytes)}`}
                                                </span>
                                            </div>
                                            <progress
                                                max={progressMax}
                                                value={progressValue}
                                                aria-label="Transfer progress"
                                                style={{ width: '100%' }}
                                            />
                                            {run.error && (
                                                <p
                                                    className="inline-message inline-message-error"
                                                    role="alert"
                                                >
                                                    {run.error}
                                                </p>
                                            )}
                                        </div>
                                    )}
                                    {run?.receivedFile?.downloadUrl &&
                                        run.state === 'completed' && (
                                            <div className="request-actions">
                                                <a
                                                    className="button button-primary"
                                                    href={run.receivedFile.downloadUrl}
                                                    download={run.receivedFile.fileName}
                                                >
                                                    Download verified file
                                                </a>
                                            </div>
                                        )}
                                    <div className="request-actions">
                                        {isSender && transfer.status === 'accepted' && (
                                            <label
                                                className="button button-primary"
                                                htmlFor={`transfer-file-${transfer.transfer_id}`}
                                            >
                                                {canChooseFile ? 'Choose file' : 'File selected'}
                                                <input
                                                    id={`transfer-file-${transfer.transfer_id}`}
                                                    type="file"
                                                    aria-label="File to send"
                                                    onChange={(event) => {
                                                        const file = event.currentTarget.files?.[0];
                                                        event.currentTarget.value = '';
                                                        handleFileSelected(transfer, file);
                                                    }}
                                                    disabled={!canChooseFile}
                                                    style={{
                                                        position: 'absolute',
                                                        width: 1,
                                                        height: 1,
                                                        overflow: 'hidden',
                                                        clip: 'rect(0 0 0 0)',
                                                    }}
                                                />
                                            </label>
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
