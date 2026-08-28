import {
    apiRequest,
    type AuthenticatedDevice,
    type CurrentSession,
} from './pairingApi';
import {
    encodeBase64Url,
    signChallenge,
    type DeviceIdentity,
} from './deviceIdentity';

export type OtpBootstrap = {
    bootstrap_id: string;
    bootstrap_token: string;
    account_id: string;
    device_epoch: number;
    expires_at: string;
};

export type RegistrationChallenge = {
    challenge_id: string;
    account_id: string;
    device_id: string;
    device_epoch: number;
    nonce: string;
    origin: string;
    issued_at: string;
    expires_at: string;
    fingerprint: string;
    protocol_version: number;
    challenge_version: number;
    recovery: boolean;
    payload: Record<string, unknown>;
};

export type DeviceLoginChallenge = {
    challenge_id: string;
    account_id: string;
    device_id: string;
    device_epoch: number;
    nonce: string;
    origin: string;
    issued_at: string;
    expires_at: string;
    protocol_version: number;
    challenge_version: number;
    payload: Record<string, unknown>;
};

export type AuthenticatedSession = {
    session_id: string;
    device_id: string;
    created_at: string;
    last_seen_at: string;
    idle_expires_at: string;
    absolute_expires_at: string;
    revoked_at: string | null;
    revocation_reason?: string | null;
};

export type AuthenticatedResult = {
    authenticated: true;
    account_id: string;
    device: AuthenticatedDevice;
    session: AuthenticatedSession;
    csrf_token: string;
    recovery: boolean;
    warning: string | null;
};

function jsonBody(value: unknown): string {
    return JSON.stringify(value);
}

function accountPath(recovery: boolean, suffix: 'challenge' | 'complete'): string {
    if (recovery) {
        return `/auth/recovery/${suffix}`;
    }
    return suffix === 'challenge'
        ? '/auth/devices/registration-challenge'
        : '/auth/devices/registration';
}

export async function startOtp(email: string): Promise<{ message: string }> {
    return apiRequest<{ message: string }>('/auth/otp/start', {
        method: 'POST',
        body: jsonBody({ email }),
    });
}

export async function verifyOtp(email: string, otp: string): Promise<OtpBootstrap> {
    return apiRequest<OtpBootstrap>('/auth/otp/verify', {
        method: 'POST',
        body: jsonBody({ email, otp }),
    });
}

export async function issueRegistrationChallenge(
    bootstrapToken: string,
    identity: DeviceIdentity,
    label: string,
    recovery = false,
): Promise<RegistrationChallenge> {
    return apiRequest<RegistrationChallenge>(accountPath(recovery, 'challenge'), {
        method: 'POST',
        body: jsonBody({
            bootstrap_token: bootstrapToken,
            device_id: identity.deviceId,
            label,
            public_key_spki: encodeBase64Url(identity.publicKeySpki),
        }),
    });
}

export async function completeRegistration(
    challenge: RegistrationChallenge,
    identity: DeviceIdentity,
): Promise<AuthenticatedResult> {
    const signature = await signChallenge(identity, challenge.payload);
    return apiRequest<AuthenticatedResult>(accountPath(challenge.recovery, 'complete'), {
        method: 'POST',
        body: jsonBody({
            challenge_id: challenge.challenge_id,
            signature,
        }),
    });
}

export async function issueDeviceLoginChallenge(
    accountId: string,
    identity: DeviceIdentity,
): Promise<DeviceLoginChallenge> {
    return apiRequest<DeviceLoginChallenge>('/auth/devices/challenge', {
        method: 'POST',
        body: jsonBody({ account_id: accountId, device_id: identity.deviceId }),
    });
}

export async function completeDeviceLogin(
    challenge: DeviceLoginChallenge,
    identity: DeviceIdentity,
): Promise<AuthenticatedResult> {
    const signature = await signChallenge(identity, challenge.payload);
    return apiRequest<AuthenticatedResult>('/auth/devices/challenge/verify', {
        method: 'POST',
        body: jsonBody({
            account_id: challenge.account_id,
            challenge_id: challenge.challenge_id,
            nonce: challenge.nonce,
            signature,
        }),
    });
}

export async function listDevices(): Promise<AuthenticatedDevice[]> {
    const body = await apiRequest<{ devices?: AuthenticatedDevice[] }>('/auth/devices');
    return Array.isArray(body.devices) ? body.devices : [];
}

export async function renameDevice(
    deviceId: string,
    label: string,
): Promise<AuthenticatedDevice> {
    const body = await apiRequest<{ device: AuthenticatedDevice }>(
        `/auth/devices/${encodeURIComponent(deviceId)}`,
        {
            method: 'PATCH',
            body: jsonBody({ label }),
        },
    );
    return body.device;
}

export async function revokeDevice(deviceId: string): Promise<AuthenticatedDevice> {
    const body = await apiRequest<{ device: AuthenticatedDevice }>(
        `/auth/devices/${encodeURIComponent(deviceId)}`,
        { method: 'DELETE' },
    );
    return body.device;
}

export async function listSessions(): Promise<AuthenticatedSession[]> {
    const body = await apiRequest<{ sessions?: AuthenticatedSession[] }>('/auth/sessions');
    return Array.isArray(body.sessions) ? body.sessions : [];
}

export async function logout(): Promise<void> {
    await apiRequest('/auth/session/logout', { method: 'POST' });
}

export type { AuthenticatedDevice, CurrentSession };
