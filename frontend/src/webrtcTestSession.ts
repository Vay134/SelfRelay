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

export type PeerConnectionFactory = (configuration?: RTCConfiguration) => RTCPeerConnection;

export type WebRtcTestSessionOptions = {
    transfer: TransferRequest;
    role: WebRtcTestRole;
    sendSignal: (message: SignalingEnvelope) => boolean | void | Promise<boolean | void>;
    peerConnectionFactory?: PeerConnectionFactory;
    rtcConfiguration?: RTCConfiguration;
    onStateChange?: (state: WebRtcTestState) => void;
    onDataChannel?: (channel: RTCDataChannel) => void;
    signingKey?: CryptoKey;
    peerSigningPublicKey?: CryptoKey | Uint8Array;
    accountEpoch?: number;
    onHandshake?: (material: DerivedHandshakeMaterial) => void;
};

export class WebRtcTestSession {
    readonly peerConnection: RTCPeerConnection;
    private readonly transfer: TransferRequest;
    private readonly role: WebRtcTestRole;
    private readonly sendSignal: WebRtcTestSessionOptions['sendSignal'];
    private readonly onStateChange?: (state: WebRtcTestState) => void;
    private readonly onDataChannel?: (channel: RTCDataChannel) => void;
    private readonly signingKey?: CryptoKey;
    private readonly peerSigningPublicKey?: CryptoKey | Uint8Array;
    private readonly accountEpoch?: number;
    private readonly onHandshake?: (material: DerivedHandshakeMaterial) => void;
    private stateValue: WebRtcTestState = 'idle';
    private dataChannel: RTCDataChannel | null = null;
    private remoteDescriptionReady = false;
    private pendingCandidates: RTCIceCandidateInit[] = [];
    private started = false;
    private handshakeOffer: SignedHandshakeOffer | null = null;
    private handshakeEphemeralPrivateKey: CryptoKey | null = null;
    private materialValue: DerivedHandshakeMaterial | null = null;

    constructor(options: WebRtcTestSessionOptions) {
        this.transfer = options.transfer;
        this.role = options.role;
        this.sendSignal = options.sendSignal;
        this.onStateChange = options.onStateChange;
        this.onDataChannel = options.onDataChannel;
        this.signingKey = options.signingKey;
        this.peerSigningPublicKey = options.peerSigningPublicKey;
        this.accountEpoch = options.accountEpoch;
        this.onHandshake = options.onHandshake;
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

    async start(): Promise<void> {
        if (this.started || this.stateValue === 'closed') {
            return;
        }
        this.started = true;
        this.setState('negotiating');
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
            this.setState('connected');
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
        this.onStateChange?.(state);
    }
}
