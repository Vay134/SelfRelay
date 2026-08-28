import {
    canonicalJsonBytes,
    copyBytes,
    decodeBase64Url,
    encodeBase64Url,
    type ByteInput,
    type DerivedHandshakeMaterial,
    FrameStream,
    importP256Spki,
    MAX_FRAME_PLAINTEXT_BYTES,
    parseCanonicalJson,
    ProtocolError,
    signP256,
    verifyP256,
} from './transferProtocol';

export const MAX_TRANSFER_BYTES = 250 * 1024 * 1024;
export const MAX_FILE_BYTES = MAX_TRANSFER_BYTES;
export const DEFAULT_CHUNK_SIZE = MAX_FRAME_PLAINTEXT_BYTES;
export const MAX_CHUNK_SIZE = MAX_FRAME_PLAINTEXT_BYTES;
export const DEFAULT_HIGH_WATER_MARK = 1024 * 1024;
export const DEFAULT_LOW_WATER_MARK = 256 * 1024;
export const MAX_FILE_NAME_BYTES = 255;
export const MAX_MEDIA_TYPE_BYTES = 127;

export type TransferRole = 'sender' | 'recipient';

export type FileTransferState =
    | 'idle'
    | 'confirming'
    | 'ready'
    | 'sending'
    | 'receiving'
    | 'completed'
    | 'cancelled'
    | 'failed'
    | 'closed';

export type TransferProgress = {
    bytesTransferred: number;
    totalBytes: number;
    chunkCount: number;
};

export type TransferManifest = {
    file_name: string;
    media_type: string;
    byte_count: number;
    chunk_size: number;
};

export type FileComplete = {
    v: 1;
    type: 'file_complete';
    transfer_id: string;
    byte_count: number;
    chunk_count: number;
    sha256: string;
    transcript_hash: string;
};

export type TransferReceipt = {
    v: 1;
    type: 'file_receipt';
    transfer_id: string;
    byte_count: number;
    sha256: string;
    status: 'verified';
};

export type ReceivedFile = {
    blob: Blob;
    fileName: string;
    mediaType: string;
    byteCount: number;
    sha256: string;
    downloadUrl?: string;
};

export type TransferDataChannel = {
    readyState: string;
    bufferedAmount: number;
    bufferedAmountLowThreshold?: number;
    binaryType?: BinaryType;
    onopen: (() => void) | null;
    onmessage: ((event: MessageEvent) => void) | null;
    onerror: ((event: Event) => void) | null;
    onclose: (() => void) | null;
    onbufferedamountlow?: (() => void) | null;
    send(data: ArrayBuffer): void;
    close(): void;
};

type TransferMaterial = Pick<DerivedHandshakeMaterial, 'confirmation' | 'transcriptHash'> &
    Partial<
        Pick<
            DerivedHandshakeMaterial,
            | 'sendKey'
            | 'receiveKey'
            | 'sendNoncePrefix'
            | 'receiveNoncePrefix'
            | 's2rKey'
            | 'r2sKey'
            | 's2rNoncePrefix'
            | 'r2sNoncePrefix'
        >
    >;

export type FileTransferEngineOptions = {
    channel: TransferDataChannel | RTCDataChannel;
    transferId: string;
    role: TransferRole;
    material: TransferMaterial;
    signingKey?: CryptoKey;
    senderSigningPublicKey?: CryptoKey | ByteInput;
    /** Alias accepted by callers that call the sender key simply `senderPublicKey`. */
    senderPublicKey?: CryptoKey | ByteInput;
    chunkSize?: number;
    /** Maximum plaintext bytes allowed by the negotiated data-channel message size. */
    maxMessageSize?: number;
    highWaterMark?: number;
    lowWaterMark?: number;
    accepted?: boolean;
    inboundDeviceId?: string;
    deviceId?: string;
    inboundRegistry?: InboundTransferRegistry;
    onProgress?: (progress: TransferProgress) => void;
    onStateChange?: (state: FileTransferState) => void;
    onManifest?: (manifest: TransferManifest) => void;
    onReceived?: (file: ReceivedFile) => void;
    onReceipt?: (receipt: TransferReceipt) => void;
    onError?: (error: ProtocolError) => void;
};

function protocolError(error: unknown, fallbackCode = 'transfer_failed'): ProtocolError {
    if (error instanceof ProtocolError) {
        return error;
    }
    if (error instanceof Error) {
        return new ProtocolError(error.message, fallbackCode);
    }
    return new ProtocolError('The transfer failed.', fallbackCode);
}

function sameBytes(left: ByteInput, right: ByteInput): boolean {
    const a = copyBytes(left);
    const b = copyBytes(right);
    if (a.byteLength !== b.byteLength) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < a.byteLength; index += 1) {
        difference |= a[index] ^ b[index];
    }
    return difference === 0;
}

function utf8ByteLength(value: string): number {
    return new TextEncoder().encode(value).byteLength;
}

function truncateUtf8(value: string, maximumBytes: number): string {
    let result = value;
    while (result.length > 0 && utf8ByteLength(result) > maximumBytes) {
        result = result.slice(0, -1);
    }
    return result;
}

function isReservedWindowsName(value: string): boolean {
    const stem = value.split('.')[0]?.toUpperCase() ?? '';
    return /^(?:CON|PRN|AUX|NUL)$/u.test(stem) || /^(?:COM[1-9]|LPT[1-9])$/u.test(stem);
}

/** Strip path components and characters unsafe for a browser download name. */
export function sanitizeFileName(value: unknown): string {
    const source = typeof value === 'string' ? value.normalize('NFKC') : '';
    const pieces = source.split(/[\\/]/u).filter((piece) => piece.length > 0);
    let result = pieces[pieces.length - 1] ?? '';
    result = result
        .replace(/\p{Cc}/gu, '')
        .replace(/[<>:"/\\|?*]/gu, '_')
        .trim()
        .replace(/[. ]+$/gu, '');
    if (result.length === 0 || result === '.' || result === '..') {
        result = 'download';
    }
    if (isReservedWindowsName(result)) {
        result = `_${result}`;
    }
    result = truncateUtf8(result, MAX_FILE_NAME_BYTES);
    return result || 'download';
}

function sanitizeMediaType(value: unknown): string {
    if (typeof value !== 'string') {
        return 'application/octet-stream';
    }
    const candidate = value.trim();
    if (
        candidate.length === 0 ||
        utf8ByteLength(candidate) > MAX_MEDIA_TYPE_BYTES ||
        !/^[\x20-\x7e]+$/u.test(candidate)
    ) {
        return 'application/octet-stream';
    }
    return candidate;
}

function requireSafeInteger(value: unknown, name: string, minimum = 0): number {
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) {
        throw new ProtocolError(`${name} is invalid.`, 'invalid_manifest');
    }
    return value;
}

function requireExactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
    const expected = new Set(keys);
    for (const key of Object.keys(value)) {
        if (!expected.has(key)) {
            throw new ProtocolError(
                'Transfer payload contains an unknown field.',
                'invalid_payload',
            );
        }
    }
    for (const key of keys) {
        if (!Object.prototype.hasOwnProperty.call(value, key)) {
            throw new ProtocolError('Transfer payload is missing a field.', 'invalid_payload');
        }
    }
}

function record(value: unknown, code = 'invalid_payload'): Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new ProtocolError('Transfer payload must be an object.', code);
    }
    return value as Record<string, unknown>;
}

function parseManifest(value: ByteInput): TransferManifest {
    const object = record(parseCanonicalJson(value), 'invalid_manifest');
    requireExactKeys(object, ['file_name', 'media_type', 'byte_count', 'chunk_size']);
    if (
        typeof object.file_name !== 'string' ||
        utf8ByteLength(object.file_name) > MAX_FILE_NAME_BYTES
    ) {
        throw new ProtocolError('Manifest file name is invalid.', 'invalid_manifest');
    }
    if (
        typeof object.media_type !== 'string' ||
        utf8ByteLength(object.media_type) > MAX_MEDIA_TYPE_BYTES
    ) {
        throw new ProtocolError('Manifest media type is invalid.', 'invalid_manifest');
    }
    if (!/^[\x20-\x7e]*$/u.test(object.media_type)) {
        throw new ProtocolError('Manifest media type is invalid.', 'invalid_manifest');
    }
    const byteCount = requireSafeInteger(object.byte_count, 'byte_count');
    if (byteCount > MAX_TRANSFER_BYTES) {
        throw new ProtocolError('Manifest file is too large.', 'file_too_large');
    }
    const chunkSize = requireSafeInteger(object.chunk_size, 'chunk_size', 1);
    if (chunkSize > MAX_CHUNK_SIZE) {
        throw new ProtocolError('Manifest chunk size is too large.', 'invalid_manifest');
    }
    const fileName = sanitizeFileName(object.file_name);
    return {
        file_name: fileName,
        media_type: sanitizeMediaType(object.media_type),
        byte_count: byteCount,
        chunk_size: chunkSize,
    };
}

function parseComplete(value: ByteInput): { core: FileComplete; signature: Uint8Array } {
    const wrapper = record(parseCanonicalJson(value), 'invalid_complete');
    requireExactKeys(wrapper, ['core', 'signature']);
    const coreObject = record(wrapper.core, 'invalid_complete');
    requireExactKeys(coreObject, [
        'v',
        'type',
        'transfer_id',
        'byte_count',
        'chunk_count',
        'sha256',
        'transcript_hash',
    ]);
    if (coreObject.v !== 1 || coreObject.type !== 'file_complete') {
        throw new ProtocolError(
            'Completion record version or type is invalid.',
            'invalid_complete',
        );
    }
    if (typeof coreObject.transfer_id !== 'string') {
        throw new ProtocolError('Completion transfer identifier is invalid.', 'invalid_complete');
    }
    const byteCount = requireSafeInteger(coreObject.byte_count, 'byte_count');
    const chunkCount = requireSafeInteger(coreObject.chunk_count, 'chunk_count');
    if (typeof coreObject.sha256 !== 'string' || typeof coreObject.transcript_hash !== 'string') {
        throw new ProtocolError('Completion digest is invalid.', 'invalid_complete');
    }
    const digest = decodeBase64Url(coreObject.sha256, 32);
    const transcript = decodeBase64Url(coreObject.transcript_hash, 32);
    if (digest.byteLength !== 32 || transcript.byteLength !== 32) {
        throw new ProtocolError('Completion digest is invalid.', 'invalid_complete');
    }
    if (typeof wrapper.signature !== 'string') {
        throw new ProtocolError('Completion signature is invalid.', 'invalid_signature');
    }
    const signature = decodeBase64Url(wrapper.signature, 64);
    if (signature.byteLength !== 64) {
        throw new ProtocolError('Completion signature is invalid.', 'invalid_signature');
    }
    return {
        core: {
            v: 1,
            type: 'file_complete',
            transfer_id: coreObject.transfer_id,
            byte_count: byteCount,
            chunk_count: chunkCount,
            sha256: coreObject.sha256,
            transcript_hash: coreObject.transcript_hash,
        },
        signature,
    };
}

function parseReceipt(value: ByteInput): TransferReceipt {
    const object = record(parseCanonicalJson(value), 'invalid_receipt');
    requireExactKeys(object, ['v', 'type', 'transfer_id', 'byte_count', 'sha256', 'status']);
    if (object.v !== 1 || object.type !== 'file_receipt' || object.status !== 'verified') {
        throw new ProtocolError('Receipt is invalid.', 'invalid_receipt');
    }
    if (typeof object.transfer_id !== 'string' || typeof object.sha256 !== 'string') {
        throw new ProtocolError('Receipt is invalid.', 'invalid_receipt');
    }
    const byteCount = requireSafeInteger(object.byte_count, 'byte_count');
    const digest = decodeBase64Url(object.sha256, 32);
    if (digest.byteLength !== 32) {
        throw new ProtocolError('Receipt digest is invalid.', 'invalid_receipt');
    }
    return {
        v: 1,
        type: 'file_receipt',
        transfer_id: object.transfer_id,
        byte_count: byteCount,
        sha256: object.sha256,
        status: 'verified',
    };
}

const SHA256_INITIAL = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
] as const;

const SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
] as const;

function rotateRight(value: number, amount: number): number {
    return (value >>> amount) | (value << (32 - amount));
}

/** Incremental SHA-256 for bounded browser file reads. */
export class IncrementalSha256 {
    private readonly state = new Uint32Array(SHA256_INITIAL);
    private readonly buffer = new Uint8Array(64);
    private bufferLength = 0;
    private totalBytes = 0;
    private finalized = false;
    private finalDigest: Uint8Array | undefined;

    update(value: ByteInput): this {
        if (this.finalized) {
            throw new ProtocolError('Digest is already finalized.', 'digest_finalized');
        }
        const bytes = copyBytes(value);
        if (this.totalBytes > Number.MAX_SAFE_INTEGER - bytes.byteLength) {
            throw new ProtocolError('Digest input is too large.', 'file_too_large');
        }
        this.totalBytes += bytes.byteLength;
        let offset = 0;
        if (this.bufferLength > 0) {
            const needed = 64 - this.bufferLength;
            const copied = Math.min(needed, bytes.byteLength);
            this.buffer.set(bytes.slice(0, copied), this.bufferLength);
            this.bufferLength += copied;
            offset = copied;
            if (this.bufferLength === 64) {
                this.process(this.buffer);
                this.bufferLength = 0;
            }
        }
        while (offset + 64 <= bytes.byteLength) {
            this.process(bytes.slice(offset, offset + 64));
            offset += 64;
        }
        if (offset < bytes.byteLength) {
            this.buffer.set(bytes.slice(offset), 0);
            this.bufferLength = bytes.byteLength - offset;
        }
        return this;
    }

    digest(): Uint8Array {
        if (this.finalDigest) {
            return copyBytes(this.finalDigest);
        }
        const bitLength = BigInt(this.totalBytes) * 8n;
        const paddingLength =
            this.bufferLength < 56 ? 56 - this.bufferLength : 120 - this.bufferLength;
        const padding = new Uint8Array(paddingLength + 8);
        padding[0] = 0x80;
        new DataView(padding.buffer).setBigUint64(paddingLength, bitLength, false);
        this.update(padding);
        const output = new Uint8Array(32);
        const view = new DataView(output.buffer);
        for (let index = 0; index < this.state.length; index += 1) {
            view.setUint32(index * 4, this.state[index], false);
        }
        this.finalized = true;
        this.finalDigest = output;
        return copyBytes(output);
    }

    private process(block: Uint8Array): void {
        const words = new Uint32Array(64);
        const view = new DataView(block.buffer, block.byteOffset, block.byteLength);
        for (let index = 0; index < 16; index += 1) {
            words[index] = view.getUint32(index * 4, false);
        }
        for (let index = 16; index < 64; index += 1) {
            const s0 =
                rotateRight(words[index - 15], 7) ^
                rotateRight(words[index - 15], 18) ^
                (words[index - 15] >>> 3);
            const s1 =
                rotateRight(words[index - 2], 17) ^
                rotateRight(words[index - 2], 19) ^
                (words[index - 2] >>> 10);
            words[index] = (words[index - 16] + s0 + words[index - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h] = this.state;
        for (let index = 0; index < 64; index += 1) {
            const sigma1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
            const choice = (e & f) ^ (~e & g);
            const temporary1 = (h + sigma1 + choice + SHA256_K[index] + words[index]) >>> 0;
            const sigma0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
            const majority = (a & b) ^ (a & c) ^ (b & c);
            const temporary2 = (sigma0 + majority) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + temporary1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temporary1 + temporary2) >>> 0;
        }
        this.state[0] = (this.state[0] + a) >>> 0;
        this.state[1] = (this.state[1] + b) >>> 0;
        this.state[2] = (this.state[2] + c) >>> 0;
        this.state[3] = (this.state[3] + d) >>> 0;
        this.state[4] = (this.state[4] + e) >>> 0;
        this.state[5] = (this.state[5] + f) >>> 0;
        this.state[6] = (this.state[6] + g) >>> 0;
        this.state[7] = (this.state[7] + h) >>> 0;
    }
}

export const IncrementalSHA256 = IncrementalSha256;

function validateWatermarks(high: number, low: number): void {
    if (
        !Number.isSafeInteger(high) ||
        high <= 0 ||
        !Number.isSafeInteger(low) ||
        low < 0 ||
        low >= high
    ) {
        throw new ProtocolError('Data-channel watermarks are invalid.', 'invalid_backpressure');
    }
}

/** Wait until buffered DataChannel bytes fall to the low watermark. */
export function waitForDataChannelCapacity(
    channel: TransferDataChannel | RTCDataChannel,
    highWaterMark = DEFAULT_HIGH_WATER_MARK,
    lowWaterMark = DEFAULT_LOW_WATER_MARK,
): Promise<void> {
    validateWatermarks(highWaterMark, lowWaterMark);
    if (channel.readyState === 'closed' || channel.readyState === 'closing') {
        return Promise.reject(new ProtocolError('The data channel is closed.', 'channel_closed'));
    }
    if (channel.bufferedAmount < highWaterMark) {
        return Promise.resolve();
    }
    if (channel.bufferedAmountLowThreshold !== undefined) {
        channel.bufferedAmountLowThreshold = lowWaterMark;
    }
    return new Promise<void>((resolve, reject) => {
        const previousLow = channel.onbufferedamountlow as (() => void) | null | undefined;
        const previousClose = channel.onclose as (() => void) | null;
        const previousError = channel.onerror as ((event: Event) => void) | null;
        let settled = false;
        const cleanup = (): void => {
            if (channel.onbufferedamountlow === onLow) {
                channel.onbufferedamountlow = previousLow;
            }
            if (channel.onclose === onClose) {
                channel.onclose = previousClose;
            }
            if (channel.onerror === onError) {
                channel.onerror = previousError;
            }
        };
        const finish = (error?: ProtocolError): void => {
            if (settled) {
                return;
            }
            settled = true;
            cleanup();
            if (error) {
                reject(error);
            } else {
                resolve();
            }
        };
        const check = (): void => {
            if (channel.bufferedAmount <= lowWaterMark) {
                finish();
            }
        };
        const onLow = (): void => {
            previousLow?.();
            check();
        };
        const onClose = (): void => {
            previousClose?.();
            finish(new ProtocolError('The data channel is closed.', 'channel_closed'));
        };
        const onError = (event: Event): void => {
            previousError?.call(channel, event);
            finish(new ProtocolError('The data channel failed.', 'channel_failed'));
        };
        channel.onbufferedamountlow = onLow;
        channel.onclose = onClose;
        channel.onerror = onError;
        check();
    });
}

export class InboundTransferRegistry {
    private readonly active = new Map<string, string>();

    reserve(deviceId: string, transferId: string): void {
        const existing = this.active.get(deviceId);
        if (existing !== undefined && existing !== transferId) {
            throw new ProtocolError('The device already has an inbound transfer.', 'inbound_busy');
        }
        this.active.set(deviceId, transferId);
    }

    release(deviceId: string, transferId: string): void {
        if (this.active.get(deviceId) === transferId) {
            this.active.delete(deviceId);
        }
    }
}

const defaultInboundRegistry = new InboundTransferRegistry();

function channelBytes(data: unknown): Promise<Uint8Array> {
    if (typeof data === 'string') {
        return Promise.reject(new ProtocolError('Text frames are not supported.', 'invalid_frame'));
    }
    if (data instanceof Blob) {
        return data.arrayBuffer().then((value) => new Uint8Array(value));
    }
    if (data instanceof ArrayBuffer) {
        return Promise.resolve(new Uint8Array(data.slice(0)));
    }
    if (ArrayBuffer.isView(data)) {
        return Promise.resolve(copyBytes(data));
    }
    return Promise.reject(new ProtocolError('Data-channel payload is invalid.', 'invalid_frame'));
}

function resolveMaterial(
    material: TransferMaterial,
    role: TransferRole,
): {
    sendKey: CryptoKey;
    receiveKey: CryptoKey;
    sendNoncePrefix: Uint8Array;
    receiveNoncePrefix: Uint8Array;
} {
    const sendKey = material.sendKey ?? (role === 'sender' ? material.s2rKey : material.r2sKey);
    const receiveKey =
        material.receiveKey ?? (role === 'sender' ? material.r2sKey : material.s2rKey);
    const sendNoncePrefix =
        material.sendNoncePrefix ??
        (role === 'sender' ? material.s2rNoncePrefix : material.r2sNoncePrefix);
    const receiveNoncePrefix =
        material.receiveNoncePrefix ??
        (role === 'sender' ? material.r2sNoncePrefix : material.s2rNoncePrefix);
    if (!sendKey || !receiveKey || !sendNoncePrefix || !receiveNoncePrefix) {
        throw new ProtocolError(
            'Directional handshake material is incomplete.',
            'invalid_material',
        );
    }
    return {
        sendKey,
        receiveKey,
        sendNoncePrefix: copyBytes(sendNoncePrefix),
        receiveNoncePrefix: copyBytes(receiveNoncePrefix),
    };
}

function asFileName(file: Blob, fallback?: string): string {
    const candidate =
        fallback ?? ('name' in file ? (file as Blob & { name?: unknown }).name : undefined);
    return sanitizeFileName(candidate);
}

function fileMediaType(file: Blob): string {
    return sanitizeMediaType('type' in file ? (file as Blob & { type?: unknown }).type : undefined);
}

export class FileTransferEngine {
    readonly channel: TransferDataChannel;
    readonly transferId: string;
    readonly role: TransferRole;
    readonly stream: FrameStream;
    readonly chunkSize: number;

    private readonly material: TransferMaterial;
    private readonly keys: ReturnType<typeof resolveMaterial>;
    private readonly signingKey?: CryptoKey;
    private readonly senderSigningPublicKey?: CryptoKey | ByteInput;
    private readonly highWaterMark: number;
    private readonly lowWaterMark: number;
    private readonly onProgress?: (progress: TransferProgress) => void;
    private readonly onStateChange?: (state: FileTransferState) => void;
    private readonly onManifest?: (manifest: TransferManifest) => void;
    private readonly onReceived?: (file: ReceivedFile) => void;
    private readonly onReceipt?: (receipt: TransferReceipt) => void;
    private readonly onError?: (error: ProtocolError) => void;
    private readonly inboundDeviceId?: string;
    private readonly inboundRegistry: InboundTransferRegistry;
    private accepted = true;
    private stateValue: FileTransferState = 'idle';
    private started = false;
    private confirmationPromise: Promise<void> | undefined;
    private confirmationResolve: (() => void) | undefined;
    private confirmationReject: ((error: ProtocolError) => void) | undefined;
    private receiveQueue: Promise<void> = Promise.resolve();
    private sentConfirmationPromise: Promise<void> | undefined;
    private completionSent = false;
    private receiptPromise: Promise<TransferReceipt> | undefined;
    private receiptResolve: ((receipt: TransferReceipt) => void) | undefined;
    private receiptReject: ((error: ProtocolError) => void) | undefined;
    private manifest: TransferManifest | undefined;
    private receiverDigest: IncrementalSha256 | undefined;
    private receiverChunks: Uint8Array[] = [];
    private receivedBytes = 0;
    private receivedChunks = 0;
    private receivedFileValue: ReceivedFile | undefined;
    private terminalError: ProtocolError | undefined;
    private previousOpen: (() => void) | null;
    private previousMessage: ((event: MessageEvent) => void) | null;
    private previousError: ((event: Event) => void) | null;
    private previousClose: (() => void) | null;

    constructor(options: FileTransferEngineOptions) {
        this.channel = options.channel as TransferDataChannel;
        this.transferId = options.transferId;
        this.role = options.role;
        this.material = options.material;
        this.keys = resolveMaterial(options.material, options.role);
        if (
            copyBytes(options.material.confirmation).byteLength !== 32 ||
            copyBytes(options.material.transcriptHash).byteLength !== 32
        ) {
            throw new ProtocolError(
                'Handshake confirmation material is invalid.',
                'invalid_material',
            );
        }
        this.signingKey = options.signingKey;
        this.senderSigningPublicKey = options.senderSigningPublicKey ?? options.senderPublicKey;
        if (this.role === 'sender' && !this.signingKey) {
            throw new ProtocolError('A sender signing key is required.', 'invalid_material');
        }
        if (this.role === 'recipient' && !this.senderSigningPublicKey) {
            throw new ProtocolError('A sender verification key is required.', 'invalid_material');
        }
        const negotiatedMaximum =
            options.maxMessageSize === undefined
                ? MAX_CHUNK_SIZE
                : options.maxMessageSize - 31 - 16;
        if (!Number.isSafeInteger(negotiatedMaximum) || negotiatedMaximum < 1) {
            throw new ProtocolError(
                'The negotiated message size is invalid.',
                'invalid_chunk_size',
            );
        }
        const chunkSize = options.chunkSize ?? Math.min(DEFAULT_CHUNK_SIZE, negotiatedMaximum);
        if (
            !Number.isSafeInteger(chunkSize) ||
            chunkSize < 1 ||
            chunkSize > MAX_CHUNK_SIZE ||
            chunkSize > negotiatedMaximum
        ) {
            throw new ProtocolError('The chunk size is invalid.', 'invalid_chunk_size');
        }
        this.chunkSize = chunkSize;
        this.highWaterMark = options.highWaterMark ?? DEFAULT_HIGH_WATER_MARK;
        this.lowWaterMark = options.lowWaterMark ?? DEFAULT_LOW_WATER_MARK;
        validateWatermarks(this.highWaterMark, this.lowWaterMark);
        this.onProgress = options.onProgress;
        this.onStateChange = options.onStateChange;
        this.onManifest = options.onManifest;
        this.onReceived = options.onReceived;
        this.onReceipt = options.onReceipt;
        this.onError = options.onError;
        this.accepted = options.accepted ?? true;
        this.inboundDeviceId = options.inboundDeviceId ?? options.deviceId;
        this.inboundRegistry = options.inboundRegistry ?? defaultInboundRegistry;
        this.stream = new FrameStream({
            transferId: this.transferId,
            direction: this.role === 'sender' ? 's2r' : 'r2s',
            confirmation: options.material.confirmation,
        });
        if (this.role === 'recipient' && this.inboundDeviceId) {
            this.inboundRegistry.reserve(this.inboundDeviceId, this.transferId);
        }
        this.previousOpen = this.channel.onopen;
        this.previousMessage = this.channel.onmessage;
        this.previousError = this.channel.onerror;
        this.previousClose = this.channel.onclose;
        this.channel.binaryType = 'arraybuffer';
        this.channel.onopen = () => {
            this.previousOpen?.();
            void this.start().catch((error: unknown) => this.fail(error));
        };
        this.channel.onmessage = (event) => {
            this.previousMessage?.(event);
            void this.handleMessage(event.data).catch(() => undefined);
        };
        this.channel.onerror = (event) => {
            this.previousError?.(event);
            this.fail(new ProtocolError('The data channel failed.', 'channel_failed'), false);
        };
        this.channel.onclose = () => {
            this.previousClose?.();
            if (!this.isTerminal()) {
                this.fail(new ProtocolError('The data channel closed.', 'channel_closed'), false);
            }
        };
        if (this.channel.readyState === 'open') {
            void this.start().catch((error: unknown) => this.fail(error));
        }
    }

    get state(): FileTransferState {
        return this.stateValue;
    }

    get receivedFile(): ReceivedFile | null {
        return this.receivedFileValue ?? null;
    }

    get receivedManifest(): TransferManifest | null {
        return this.manifest ? { ...this.manifest } : null;
    }

    get isConfirmed(): boolean {
        return this.stream.isConfirmed;
    }

    async start(): Promise<void> {
        if (this.isTerminal()) {
            return;
        }
        this.started = true;
        if (this.stateValue === 'idle') {
            this.setState('confirming');
        }
        if (this.channel.readyState !== 'open') {
            return;
        }
        await this.sendConfirmation();
    }

    accept(): void {
        if (this.role !== 'recipient' || this.manifest) {
            throw new ProtocolError(
                'The transfer cannot be accepted in its current state.',
                'invalid_state',
            );
        }
        this.accepted = true;
    }

    reject(code = 'rejected'): Promise<void> {
        return this.sendTerminalFrame('cancel', code, 'cancelled');
    }

    async sendFile(file: Blob, fileName?: string): Promise<TransferReceipt> {
        if (this.role !== 'sender') {
            throw new ProtocolError('Only the sender can send a file.', 'invalid_state');
        }
        if (this.isTerminal() || this.completionSent) {
            throw (
                this.terminalError ??
                new ProtocolError('The transfer is not available.', 'invalid_state')
            );
        }
        const input = file as Blob & {
            size: number;
            slice: (start?: number, end?: number) => Blob;
        };
        if (!input || typeof input.size !== 'number' || typeof input.slice !== 'function') {
            throw new ProtocolError('The selected file is invalid.', 'invalid_file');
        }
        if (
            !Number.isSafeInteger(input.size) ||
            input.size < 0 ||
            input.size > MAX_TRANSFER_BYTES
        ) {
            throw new ProtocolError('The selected file is too large.', 'file_too_large');
        }
        if (!this.signingKey) {
            throw new ProtocolError('A sender signing key is required.', 'invalid_material');
        }
        await this.start();
        await this.waitForConfirmation();
        this.setState('sending');
        const manifest: TransferManifest = {
            file_name: asFileName(input, fileName),
            media_type: fileMediaType(input),
            byte_count: input.size,
            chunk_size: this.chunkSize,
        };
        await this.sendFrame('manifest', canonicalJsonBytes(manifest));
        const digest = new IncrementalSha256();
        let offset = 0;
        let chunkCount = 0;
        while (offset < input.size) {
            const nextOffset = Math.min(offset + this.chunkSize, input.size);
            const chunk = await this.readSlice(input, offset, nextOffset);
            if (chunk.byteLength !== nextOffset - offset) {
                throw new ProtocolError('The file changed while reading.', 'file_read_failed');
            }
            digest.update(chunk);
            await this.sendFrame('chunk', chunk);
            offset = nextOffset;
            chunkCount += 1;
            this.progress(offset, input.size, chunkCount);
        }
        const core: FileComplete = {
            v: 1,
            type: 'file_complete',
            transfer_id: this.transferId,
            byte_count: input.size,
            chunk_count: chunkCount,
            sha256: encodeBase64Url(digest.digest()),
            transcript_hash: encodeBase64Url(this.material.transcriptHash),
        };
        const signature = encodeBase64Url(
            await signP256(this.signingKey, canonicalJsonBytes(core)),
        );
        this.receiptPromise = new Promise<TransferReceipt>((resolve, reject) => {
            this.receiptResolve = resolve;
            this.receiptReject = reject;
        });
        this.completionSent = true;
        await this.sendFrame('complete', canonicalJsonBytes({ core, signature }));
        return this.receiptPromise;
    }

    async handleMessage(data: unknown): Promise<void> {
        if (this.isTerminal()) {
            return;
        }
        const operation = this.receiveQueue.then(async () => {
            const bytes = await channelBytes(data);
            const result = await this.stream.receiveFrame(
                this.keys.receiveKey,
                this.keys.receiveNoncePrefix,
                bytes,
            );
            if (result.header.type === 'confirm') {
                await this.handleConfirmation();
                return;
            }
            if (result.header.type === 'manifest') {
                await this.handleManifest(result.plaintext);
                return;
            }
            if (result.header.type === 'chunk') {
                this.handleChunk(result.plaintext);
                return;
            }
            if (result.header.type === 'complete') {
                await this.handleComplete(result.plaintext);
                return;
            }
            if (result.header.type === 'receipt') {
                this.handleReceipt(result.plaintext);
                return;
            }
            if (result.header.type === 'cancel' || result.header.type === 'error') {
                this.handleTerminalPayload(result.plaintext, result.header.type);
            }
        });
        this.receiveQueue = operation.catch((error: unknown) => {
            this.fail(error);
            throw error;
        });
        return operation;
    }

    close(): void {
        if (this.stateValue === 'closed') {
            return;
        }
        this.cleanupReceiver();
        this.releaseInbound();
        this.rejectPending(new ProtocolError('The transfer was closed.', 'closed'));
        this.setState('closed');
        if (this.channel.readyState !== 'closed') {
            this.channel.close();
        }
    }

    dispose(): void {
        this.close();
        if (this.receivedFileValue?.downloadUrl && typeof URL.revokeObjectURL === 'function') {
            URL.revokeObjectURL(this.receivedFileValue.downloadUrl);
            this.receivedFileValue = { ...this.receivedFileValue, downloadUrl: undefined };
        }
    }

    private async sendConfirmation(): Promise<void> {
        if (this.sentConfirmationPromise) {
            return this.sentConfirmationPromise;
        }
        if (this.stream.nextSendCounter !== 0n) {
            return;
        }
        this.sentConfirmationPromise = this.sendFrame('confirm', this.material.confirmation, true);
        try {
            await this.sentConfirmationPromise;
        } catch (error) {
            this.sentConfirmationPromise = undefined;
            throw error;
        }
    }

    private async waitForConfirmation(): Promise<void> {
        if (this.stream.isConfirmed) {
            return;
        }
        if (!this.confirmationPromise) {
            this.confirmationPromise = new Promise<void>((resolve, reject) => {
                this.confirmationResolve = resolve;
                this.confirmationReject = reject;
            });
        }
        return this.confirmationPromise;
    }

    private async handleConfirmation(): Promise<void> {
        if (!this.sentConfirmationPromise) {
            await this.sendConfirmation();
        }
        if (this.stream.isConfirmed) {
            this.confirmationResolve?.();
            this.confirmationResolve = undefined;
            this.confirmationReject = undefined;
            if (this.stateValue === 'confirming') {
                this.setState('ready');
            }
        }
    }

    private async sendFrame(
        type: 'confirm' | 'manifest' | 'chunk' | 'complete' | 'receipt' | 'cancel' | 'error',
        plaintext: ByteInput,
        confirmation = false,
    ): Promise<void> {
        if (this.isTerminal()) {
            throw (
                this.terminalError ??
                new ProtocolError('The transfer is not available.', 'invalid_state')
            );
        }
        if (this.channel.readyState !== 'open') {
            throw new ProtocolError('The data channel is not open.', 'channel_not_open');
        }
        if (!confirmation && !this.stream.isConfirmed) {
            throw new ProtocolError('Peer confirmation is required.', 'confirmation_required');
        }
        const frame = await this.stream.createFrame(
            this.keys.sendKey,
            this.keys.sendNoncePrefix,
            type,
            plaintext,
        );
        await waitForDataChannelCapacity(this.channel, this.highWaterMark, this.lowWaterMark);
        if (this.channel.readyState !== 'open') {
            throw new ProtocolError('The data channel is not open.', 'channel_closed');
        }
        this.channel.send(frame.slice().buffer as ArrayBuffer);
    }

    private async handleManifest(value: ByteInput): Promise<void> {
        if (this.role !== 'recipient') {
            throw new ProtocolError('A sender cannot receive a manifest.', 'invalid_state');
        }
        if (!this.accepted) {
            throw new ProtocolError('The transfer was not accepted.', 'not_accepted');
        }
        if (this.manifest) {
            throw new ProtocolError('The manifest was duplicated.', 'invalid_state');
        }
        this.manifest = parseManifest(value);
        this.receiverDigest = new IncrementalSha256();
        this.setState('receiving');
        this.onManifest?.({ ...this.manifest });
    }

    private handleChunk(value: ByteInput): void {
        if (this.role !== 'recipient' || !this.manifest || !this.receiverDigest) {
            throw new ProtocolError('A chunk arrived before the manifest.', 'invalid_state');
        }
        const chunk = copyBytes(value);
        const remaining = this.manifest.byte_count - this.receivedBytes;
        if (
            remaining <= 0 ||
            chunk.byteLength === 0 ||
            chunk.byteLength > this.manifest.chunk_size ||
            chunk.byteLength > remaining
        ) {
            throw new ProtocolError('Chunk size is invalid.', 'invalid_chunk');
        }
        const isFinalChunk = chunk.byteLength === remaining;
        if (!isFinalChunk && chunk.byteLength !== this.manifest.chunk_size) {
            throw new ProtocolError('A non-final chunk has the wrong size.', 'invalid_chunk');
        }
        this.receiverDigest.update(chunk);
        this.receiverChunks.push(chunk);
        this.receivedBytes += chunk.byteLength;
        this.receivedChunks += 1;
        this.progress(this.receivedBytes, this.manifest.byte_count, this.receivedChunks);
    }

    private async handleComplete(value: ByteInput): Promise<void> {
        if (this.role !== 'recipient' || !this.manifest || !this.receiverDigest) {
            throw new ProtocolError('Completion arrived before the manifest.', 'invalid_state');
        }
        const { core, signature } = parseComplete(value);
        if (
            core.transfer_id !== this.transferId ||
            core.byte_count !== this.manifest.byte_count ||
            core.chunk_count !== this.receivedChunks ||
            this.receivedBytes !== this.manifest.byte_count
        ) {
            throw new ProtocolError(
                'Completion counts do not match the received file.',
                'digest_mismatch',
            );
        }
        if (!sameBytes(decodeBase64Url(core.transcript_hash, 32), this.material.transcriptHash)) {
            throw new ProtocolError('Completion transcript does not match.', 'transcript_mismatch');
        }
        const digest = this.receiverDigest.digest();
        if (!sameBytes(digest, decodeBase64Url(core.sha256, 32))) {
            throw new ProtocolError('The received file digest does not match.', 'digest_mismatch');
        }
        const publicKey =
            this.senderSigningPublicKey instanceof CryptoKey
                ? this.senderSigningPublicKey
                : await importP256Spki(this.senderSigningPublicKey as ByteInput, 'signing');
        if (!(await verifyP256(publicKey, canonicalJsonBytes(core), signature))) {
            throw new ProtocolError('Completion signature is invalid.', 'invalid_signature');
        }
        const blobParts = this.receiverChunks.map((chunk) => chunk.slice().buffer as ArrayBuffer);
        const blob = new Blob(blobParts, { type: this.manifest.media_type });
        const downloadUrl =
            typeof URL.createObjectURL === 'function' ? URL.createObjectURL(blob) : undefined;
        const received: ReceivedFile = {
            blob,
            fileName: this.manifest.file_name,
            mediaType: this.manifest.media_type,
            byteCount: this.receivedBytes,
            sha256: core.sha256,
            ...(downloadUrl ? { downloadUrl } : {}),
        };
        const receipt: TransferReceipt = {
            v: 1,
            type: 'file_receipt',
            transfer_id: this.transferId,
            byte_count: this.receivedBytes,
            sha256: core.sha256,
            status: 'verified',
        };
        await this.sendFrame('receipt', canonicalJsonBytes(receipt));
        this.receivedFileValue = received;
        this.cleanupReceiverChunksOnly();
        this.setState('completed');
        this.onReceived?.(received);
    }

    private handleReceipt(value: ByteInput): void {
        if (this.role !== 'sender' || !this.completionSent) {
            throw new ProtocolError('Receipt arrived before completion.', 'invalid_state');
        }
        const receipt = parseReceipt(value);
        if (receipt.transfer_id !== this.transferId) {
            throw new ProtocolError(
                'Receipt transfer identifier does not match.',
                'identity_mismatch',
            );
        }
        this.receiptResolve?.(receipt);
        this.receiptResolve = undefined;
        this.receiptReject = undefined;
        this.setState('completed');
        this.onReceipt?.(receipt);
    }

    private handleTerminalPayload(value: ByteInput, type: 'cancel' | 'error'): void {
        const object = record(parseCanonicalJson(value), `remote_${type}`);
        requireExactKeys(object, ['v', 'type', 'code']);
        if (
            object.v !== 1 ||
            object.type !== type ||
            typeof object.code !== 'string' ||
            !/^[a-z0-9_]{1,64}$/u.test(object.code)
        ) {
            throw new ProtocolError('Remote terminal payload is invalid.', 'invalid_payload');
        }
        const error = new ProtocolError(
            type === 'cancel'
                ? 'The peer cancelled the transfer.'
                : 'The peer reported a transfer error.',
            object.code,
        );
        this.fail(error, false, false);
    }

    private async sendTerminalFrame(
        type: 'cancel' | 'error',
        code: string,
        state: 'cancelled' | 'failed',
    ): Promise<void> {
        if (this.isTerminal()) {
            return;
        }
        const safeCode = /^[a-z0-9_]{1,64}$/u.test(code) ? code : 'transfer_failed';
        try {
            await this.start();
            if (this.stream.isConfirmed) {
                await this.sendFrame(type, canonicalJsonBytes({ v: 1, type, code: safeCode }));
            }
        } finally {
            this.cleanupReceiver();
            this.releaseInbound();
            this.setState(state);
            this.rejectPending(new ProtocolError('The transfer was cancelled.', safeCode));
        }
    }

    private fail(error: unknown, notify = true, sendWire = true): void {
        if (this.isTerminal()) {
            return;
        }
        const failure = protocolError(error);
        this.terminalError = failure;
        this.cleanupReceiver();
        this.releaseInbound();
        this.rejectPending(failure);
        this.setState('failed');
        if (notify) {
            this.onError?.(failure);
        }
        if (sendWire && this.stream.isConfirmed && this.channel.readyState === 'open') {
            void this.sendTerminalFrame('error', failure.code, 'failed');
        }
    }

    private rejectPending(error: ProtocolError): void {
        this.confirmationReject?.(error);
        this.confirmationResolve = undefined;
        this.confirmationReject = undefined;
        this.receiptReject?.(error);
        this.receiptResolve = undefined;
        this.receiptReject = undefined;
    }

    private async readSlice(file: Blob, start: number, end: number): Promise<Uint8Array> {
        try {
            const slice = file.slice(start, end);
            return new Uint8Array(await slice.arrayBuffer());
        } catch {
            throw new ProtocolError('The file could not be read.', 'file_read_failed');
        }
    }

    private progress(bytesTransferred: number, totalBytes: number, chunkCount: number): void {
        this.onProgress?.({ bytesTransferred, totalBytes, chunkCount });
    }

    private cleanupReceiverChunksOnly(): void {
        this.receiverChunks = [];
        this.receiverDigest = undefined;
    }

    private cleanupReceiver(): void {
        this.cleanupReceiverChunksOnly();
        this.manifest = undefined;
        this.receivedBytes = 0;
        this.receivedChunks = 0;
    }

    private releaseInbound(): void {
        if (this.inboundDeviceId) {
            this.inboundRegistry.release(this.inboundDeviceId, this.transferId);
        }
    }

    private isTerminal(): boolean {
        return (
            this.stateValue === 'completed' ||
            this.stateValue === 'cancelled' ||
            this.stateValue === 'failed' ||
            this.stateValue === 'closed'
        );
    }

    private setState(state: FileTransferState): void {
        if (this.stateValue === state) {
            return;
        }
        this.stateValue = state;
        this.onStateChange?.(state);
    }
}

export const TransferEngine = FileTransferEngine;
export const EncryptedFileTransfer = FileTransferEngine;
