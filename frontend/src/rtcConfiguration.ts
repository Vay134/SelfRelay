import type { TurnCredentials } from './transferApi';

type FrontendEnvironment = {
    VITE_FORCE_RELAY_FOR_TESTS?: string;
};

export type RtcConfigurationOptions = {
    relayOnly?: boolean;
};

export function relayOnlyTestEnabled(
    environment: FrontendEnvironment | undefined = (
        import.meta as ImportMeta & { env?: FrontendEnvironment }
    ).env,
): boolean {
    return environment?.VITE_FORCE_RELAY_FOR_TESTS === 'true';
}

/** Keep the default ICE policy as `all` so the browser prefers direct paths. */
export function rtcConfigurationFromTurnCredentials(
    credentials: TurnCredentials,
    { relayOnly = false }: RtcConfigurationOptions = {},
): RTCConfiguration {
    return {
        iceServers: credentials.ice_servers.map((server) => ({
            urls: [...server.urls],
            username: server.username,
            credential: server.credential,
        })),
        ...(relayOnly ? { iceTransportPolicy: 'relay' } : {}),
    };
}
