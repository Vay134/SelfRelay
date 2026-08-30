import {
    buildHandshakeAnswerEnvelope,
    buildHandshakeOfferEnvelope,
    buildIceCandidateEnvelope,
    buildSdpAnswerEnvelope,
    buildSdpOfferEnvelope,
    type IceCandidateInput,
    type SignalingEnvelope,
    type TransferRequest,
} from './transferApi';
import {
    assertValidHandshakeAnswer,
    assertValidHandshakeOffer,
    createHandshakeAnswer,
    createHandshakeOffer,
    decodeBase64Url,
    deriveHandshakeMaterial,
    type DerivedHandshakeMaterial,
    type SignedHandshakeOffer,
} from './transferProtocol';

export type WebRtcTestRole = 'sender' | 'recipient';

export type WebRtcTestState = 'idle' | 'negotiating' | 'connected' | 'failed' | 'closed';

export type WebRtcRelayStatus = 'unknown' | 'direct' | 'relay';

export type PeerConnectionFactory = (configuration?: RTCConfiguration) => RTCPeerConnection;

export const MAX_PENDING_ICE_CANDIDATES = 64;
export const DEFAULT_NEGOTIATION_TIMEOUT_MS = 30_000;
const RELAY_STATUS_REFRESH_DELAY_MS = 250;
const MAX_RELAY_STATUS_REFRESH_ATTEMPTS = 4;

export type WebRtcTestSessionOptions = {
    transfer: TransferRequest;
    role: WebRtcTestRole;
    sendSignal: (message: SignalingEnvelope) => boolean | void | Promise<boolean | void>;
    peerConnectionFactory?: PeerConnectionFactory;
    rtcConfiguration?: RTCConfiguration;
    onStateChange?: (state: WebRtcTestState) => void;
    onDataChannel?: (channel: RTCDataChannel) => void;
    onRelayStatusChange?: (status: WebRtcRelayStatus) => void;
    signingKey?: CryptoKey;
    peerSigningPublicKey?: CryptoKey | Uint8Array;
    accountEpoch?: number;
    onHandshake?: (material: DerivedHandshakeMaterial) => void;
    negotiationTimeoutMs?: number;
};

export class WebRtcTestSession {
    readonly peerConnection: RTCPeerConnection;
    private readonly transfer: TransferRequest;
    private readonly role: WebRtcTestRole;
    private readonly sendSignal: WebRtcTestSessionOptions['sendSignal'];
    private readonly onStateChange?: (state: WebRtcTestState) => void;
    private readonly onDataChannel?: (channel: RTCDataChannel) => void;
    private readonly onRelayStatusChange?: (status: WebRtcRelayStatus) => void;
    private readonly signingKey?: CryptoKey;
    private readonly peerSigningPublicKey?: CryptoKey | Uint8Array;
    private readonly accountEpoch?: number;
    private readonly onHandshake?: (material: DerivedHandshakeMaterial) => void;
    private readonly negotiationTimeoutMs: number;
    private stateValue: WebRtcTestState = 'idle';
    private dataChannel: RTCDataChannel | null = null;
    private remoteDescriptionReady = false;
    private pendingCandidates: RTCIceCandidateInit[] = [];
    private started = false;
    private handshakeOffer: SignedHandshakeOffer | null = null;
    private handshakeEphemeralPrivateKey: CryptoKey | null = null;
    private materialValue: DerivedHandshakeMaterial | null = null;
    private relayStatusValue: WebRtcRelayStatus = 'unknown';
    private negotiationTimer: ReturnType<typeof setTimeout> | null = null;
    private relayStatusRefreshTimer: ReturnType<typeof setTimeout> | null = null;
    private relayStatusRefreshAttempts = 0;

    constructor(options: WebRtcTestSessionOptions) {
        this.transfer = options.transfer;
        this.role = options.role;
        this.sendSignal = options.sendSignal;
        this.onStateChange = options.onStateChange;
        this.onDataChannel = options.onDataChannel;
        this.onRelayStatusChange = options.onRelayStatusChange;
        this.signingKey = options.signingKey;
        this.peerSigningPublicKey = options.peerSigningPublicKey;
        this.accountEpoch = options.accountEpoch;
        this.onHandshake = options.onHandshake;
        this.negotiationTimeoutMs = options.negotiationTimeoutMs ?? DEFAULT_NEGOTIATION_TIMEOUT_MS;
        if (!Number.isFinite(this.negotiationTimeoutMs) || this.negotiationTimeoutMs <= 0) {
            throw new TypeError('The negotiation timeout must be positive.');
        }
        const createPeerConnection =
            options.peerConnectionFactory ??
            ((configuration) => new RTCPeerConnection(configuration));
        this.peerConnection = createPeerConnection(options.rtcConfiguration);
        this.peerConnection.onicecandidate = (event) => {
            if (!event.candidate) {
                return;
            }
            const candidate: IceCandidateInput = {
                candidate: event.candidate.candidate,
                sdpMid: event.candidate.sdpMid,
                sdpMLineIndex: event.candidate.sdpMLineIndex,
                usernameFragment: event.candidate.usernameFragment,
            };
            void this.emitSignal(buildIceCandidateEnvelope(this.transfer, candidate)).catch(() => {
                this.setState('failed');
            });
        };
        this.peerConnection.ondatachannel = (event) => {
            this.attachDataChannel(event.channel);
        };
        this.peerConnection.onconnectionstatechange = () => {
            if (this.peerConnection.connectionState === 'connected') {
                this.setState('connected');
                void this.refreshRelayStatus();
            } else if (
                this.peerConnection.connectionState === 'failed' ||
                this.peerConnection.connectionState === 'closed'
            ) {
                this.setState(this.peerConnection.connectionState);
            }
        };
    }

    get state(): WebRtcTestState {
        return this.stateValue;
    }

    get material(): DerivedHandshakeMaterial | null {
        return this.materialValue;
    }

    get relayStatus(): WebRtcRelayStatus {
        return this.relayStatusValue;
    }

    async start(): Promise<void> {
        if (this.started || this.stateValue === 'closed') {
            return;
        }
        this.started = true;
        this.setState('negotiating');
        this.armNegotiationTimeout();
        try {
            if (this.role !== 'sender') {
                return;
            }

            if (!this.signingKey || !this.peerSigningPublicKey || this.accountEpoch === undefined) {
                throw new Error('Authenticated handshake material is required.');
            }
            const offer = await createHandshakeOffer({
                transferId: this.transfer.transfer_id,
                accountEpoch: this.accountEpoch,
                senderDeviceId: this.transfer.sender_device_id,
                recipientDeviceId: this.transfer.recipient_device_id,
                expiresAt: new Date(this.transfer.expires_at).getTime(),
                signingKey: this.signingKey,
            });
            this.handshakeOffer = offer;
            this.handshakeEphemeralPrivateKey = offer.ephemeralKeyPair.privateKey;
            await this.emitSignal(buildHandshakeOfferEnvelope(this.transfer, offer));
        } catch (error) {
            this.setState('failed');
            throw error;
        }
    }

    private async startNegotiation(): Promise<void> {
        if (this.role !== 'sender') {
            return;
        }

        const channel = this.peerConnection.createDataChannel('secure-transfer-test', {
            ordered: true,
        });
        this.attachDataChannel(channel);
        const offer = await this.peerConnection.createOffer();
        await this.peerConnection.setLocalDescription(offer);
        const localDescription = this.peerConnection.localDescription ?? offer;
        if (!localDescription.sdp) {
            throw new Error('The browser did not create an SDP offer.');
        }
        await this.emitSignal(buildSdpOfferEnvelope(this.transfer, localDescription.sdp));
    }

    async handleSignal(message: SignalingEnvelope): Promise<boolean> {
        if (
            this.stateValue === 'closed' ||
            message.transfer_id !== this.transfer.transfer_id ||
            message.sender_device_id !== this.transfer.sender_device_id ||
            message.recipient_device_id !== this.transfer.recipient_device_id
        ) {
            return false;
        }
        if (message.type === 'ice_candidate') {
            await this.handleIceCandidate(message);
            return true;
        }
        if (message.type === 'handshake_offer') {
            if (
                this.role !== 'recipient' ||
                !this.signingKey ||
                !this.peerSigningPublicKey ||
                this.accountEpoch === undefined
            ) {
                return false;
            }
            const offer = await assertValidHandshakeOffer(
                message.handshake,
                this.peerSigningPublicKey,
                {
                    transferId: this.transfer.transfer_id,
                    accountEpoch: this.accountEpoch,
                    senderDeviceId: this.transfer.sender_device_id,
                    recipientDeviceId: this.transfer.recipient_device_id,
                },
            );
            const answer = await createHandshakeAnswer({
                transferId: this.transfer.transfer_id,
                accountEpoch: this.accountEpoch,
                senderDeviceId: this.transfer.sender_device_id,
                recipientDeviceId: this.transfer.recipient_device_id,
                offer: message.handshake,
                expiresAt: offer.expires_at,
                signingKey: this.signingKey,
            });
            this.materialValue = await deriveHandshakeMaterial({
                offer,
                answer: answer.core,
                localEphemeralPrivateKey: answer.ephemeralKeyPair.privateKey,
                remoteEphemeralSpki: decodeBase64Url(offer.sender_ephemeral_spki, 1024),
                role: 'recipient',
            });
            this.onHandshake?.(this.materialValue);
            await this.emitSignal(buildHandshakeAnswerEnvelope(this.transfer, answer));
            return true;
        }
        if (message.type === 'handshake_answer') {
            if (
                this.role !== 'sender' ||
                !this.handshakeOffer ||
                !this.handshakeEphemeralPrivateKey ||
                !this.peerSigningPublicKey ||
                this.accountEpoch === undefined
            ) {
                return false;
            }
            const answer = await assertValidHandshakeAnswer(
                message.handshake,
                this.peerSigningPublicKey,
                {
                    offer: this.handshakeOffer,
                    transferId: this.transfer.transfer_id,
                    accountEpoch: this.accountEpoch,
                    senderDeviceId: this.transfer.sender_device_id,
                    recipientDeviceId: this.transfer.recipient_device_id,
                },
            );
            this.materialValue = await deriveHandshakeMaterial({
                offer: this.handshakeOffer.core,
                answer,
                localEphemeralPrivateKey: this.handshakeEphemeralPrivateKey,
                remoteEphemeralSpki: decodeBase64Url(answer.recipient_ephemeral_spki, 1024),
                role: 'sender',
            });
            this.onHandshake?.(this.materialValue);
            await this.startNegotiation();
            return true;
        }
        this.started = true;
        this.setState('negotiating');
        this.armNegotiationTimeout();
        if (message.type === 'sdp_offer') {
            if (this.role !== 'recipient') {
                return false;
            }
            await this.peerConnection.setRemoteDescription({ type: 'offer', sdp: message.sdp });
            this.remoteDescriptionReady = true;
            await this.flushCandidates();
            const answer = await this.peerConnection.createAnswer();
            await this.peerConnection.setLocalDescription(answer);
            const localDescription = this.peerConnection.localDescription ?? answer;
            if (!localDescription.sdp) {
                throw new Error('The browser did not create an SDP answer.');
            }
            await this.emitSignal(buildSdpAnswerEnvelope(this.transfer, localDescription.sdp));
            return true;
        }
        if (message.type === 'sdp_answer' && this.role === 'sender') {
            await this.peerConnection.setRemoteDescription({ type: 'answer', sdp: message.sdp });
            this.remoteDescriptionReady = true;
            await this.flushCandidates();
            return true;
        }
        return false;
    }

    close(): void {
        if (this.stateValue === 'closed') {
            return;
        }
        this.dataChannel?.close();
        this.peerConnection.close();
        this.clearNegotiationTimeout();
        this.clearRelayStatusRefresh();
        this.setState('closed');
    }

    private async handleIceCandidate(
        message: Extract<SignalingEnvelope, { type: 'ice_candidate' }>,
    ) {
        const candidate: RTCIceCandidateInit = {
            candidate: message.candidate,
            sdpMid: message.sdp_mid,
            sdpMLineIndex: message.sdp_mline_index,
            usernameFragment: message.username_fragment,
        };
        if (!this.remoteDescriptionReady) {
            if (this.pendingCandidates.length >= MAX_PENDING_ICE_CANDIDATES) {
                throw new Error('The ICE candidate queue is full.');
            }
            this.pendingCandidates.push(candidate);
            return;
        }
        await this.peerConnection.addIceCandidate(candidate);
    }

    private async flushCandidates(): Promise<void> {
        const pending = this.pendingCandidates;
        this.pendingCandidates = [];
        for (const candidate of pending) {
            await this.peerConnection.addIceCandidate(candidate);
        }
    }

    private attachDataChannel(channel: RTCDataChannel): void {
        this.dataChannel = channel;
        channel.onopen = () => {
            this.onDataChannel?.(channel);
            this.clearNegotiationTimeout();
            this.setState('connected');
            void this.refreshRelayStatus();
        };
        channel.onerror = () => {
            this.setState('failed');
        };
        channel.onclose = () => {
            if (this.stateValue !== 'closed') {
                this.setState('closed');
            }
        };
    }

    private async emitSignal(message: SignalingEnvelope): Promise<void> {
        const result = await this.sendSignal(message);
        if (result === false) {
            throw new Error('The presence socket is offline.');
        }
    }

    private setState(state: WebRtcTestState): void {
        if (state === this.stateValue) {
            return;
        }
        this.stateValue = state;
        if (state === 'connected' || state === 'failed' || state === 'closed') {
            this.clearNegotiationTimeout();
        }
        this.onStateChange?.(state);
    }

    private armNegotiationTimeout(): void {
        this.clearNegotiationTimeout();
        this.negotiationTimer = setTimeout(() => {
            this.negotiationTimer = null;
            if (this.stateValue === 'negotiating') {
                this.setState('failed');
            }
        }, this.negotiationTimeoutMs);
    }

    private clearNegotiationTimeout(): void {
        if (this.negotiationTimer !== null) {
            clearTimeout(this.negotiationTimer);
            this.negotiationTimer = null;
        }
    }

    private async refreshRelayStatus(): Promise<void> {
        if (
            this.relayStatusValue !== 'unknown' ||
            this.stateValue !== 'connected' ||
            typeof this.peerConnection.getStats !== 'function'
        ) {
            return;
        }
        let stats: RTCStatsReport;
        try {
            stats = await this.peerConnection.getStats();
        } catch {
            this.scheduleRelayStatusRefresh();
            return;
        }
        const selectedPair = [...stats.values()].find((value) => {
            const report = value as {
                type?: unknown;
                state?: unknown;
                selected?: unknown;
                nominated?: unknown;
            };
            return (
                report.type === 'candidate-pair' &&
                report.state === 'succeeded' &&
                (report.selected === true || report.nominated === true)
            );
        }) as
            | {
                  localCandidateId?: unknown;
                  remoteCandidateId?: unknown;
              }
            | undefined;
        if (!selectedPair) {
            this.scheduleRelayStatusRefresh();
            return;
        }
        const localCandidate = this.candidateStats(stats, selectedPair.localCandidateId);
        const remoteCandidate = this.candidateStats(stats, selectedPair.remoteCandidateId);
        if (!localCandidate && !remoteCandidate) {
            this.scheduleRelayStatusRefresh();
            return;
        }
        const relayUsed =
            localCandidate?.candidateType === 'relay' || remoteCandidate?.candidateType === 'relay';
        this.setRelayStatus(relayUsed ? 'relay' : 'direct');
    }

    private candidateStats(
        stats: RTCStatsReport,
        candidateId: unknown,
    ): { candidateType?: unknown } | null {
        if (typeof candidateId !== 'string') {
            return null;
        }
        const value = stats.get(candidateId);
        if (typeof value !== 'object' || value === null) {
            return null;
        }
        const report = value as { type?: unknown; candidateType?: unknown };
        return report.type === 'local-candidate' || report.type === 'remote-candidate'
            ? report
            : null;
    }

    private setRelayStatus(status: WebRtcRelayStatus): void {
        if (status === this.relayStatusValue) {
            return;
        }
        this.relayStatusValue = status;
        this.clearRelayStatusRefresh();
        this.onRelayStatusChange?.(status);
    }

    private scheduleRelayStatusRefresh(): void {
        if (
            this.relayStatusRefreshTimer !== null ||
            this.relayStatusRefreshAttempts >= MAX_RELAY_STATUS_REFRESH_ATTEMPTS ||
            this.stateValue !== 'connected'
        ) {
            return;
        }
        this.relayStatusRefreshAttempts += 1;
        this.relayStatusRefreshTimer = setTimeout(() => {
            this.relayStatusRefreshTimer = null;
            void this.refreshRelayStatus();
        }, RELAY_STATUS_REFRESH_DELAY_MS);
    }

    private clearRelayStatusRefresh(): void {
        if (this.relayStatusRefreshTimer !== null) {
            clearTimeout(this.relayStatusRefreshTimer);
            this.relayStatusRefreshTimer = null;
        }
    }
}
