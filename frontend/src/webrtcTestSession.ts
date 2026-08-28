import {
    buildIceCandidateEnvelope,
    buildSdpAnswerEnvelope,
    buildSdpOfferEnvelope,
    type IceCandidateInput,
    type SignalingEnvelope,
    type TransferRequest,
} from './transferApi';

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
};

export class WebRtcTestSession {
    readonly peerConnection: RTCPeerConnection;
    private readonly transfer: TransferRequest;
    private readonly role: WebRtcTestRole;
    private readonly sendSignal: WebRtcTestSessionOptions['sendSignal'];
    private readonly onStateChange?: (state: WebRtcTestState) => void;
    private readonly onDataChannel?: (channel: RTCDataChannel) => void;
    private stateValue: WebRtcTestState = 'idle';
    private dataChannel: RTCDataChannel | null = null;
    private remoteDescriptionReady = false;
    private pendingCandidates: RTCIceCandidateInit[] = [];
    private started = false;

    constructor(options: WebRtcTestSessionOptions) {
        this.transfer = options.transfer;
        this.role = options.role;
        this.sendSignal = options.sendSignal;
        this.onStateChange = options.onStateChange;
        this.onDataChannel = options.onDataChannel;
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

    async start(): Promise<void> {
        if (this.started || this.stateValue === 'closed') {
            return;
        }
        this.started = true;
        this.setState('negotiating');
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
