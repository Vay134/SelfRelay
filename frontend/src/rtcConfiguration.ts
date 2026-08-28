import type { TurnCredentials } from './transferApi';

/** Keep the default ICE policy as `all` so the browser prefers direct paths. */
export function rtcConfigurationFromTurnCredentials(
    credentials: TurnCredentials,
): RTCConfiguration {
    return {
        iceServers: credentials.ice_servers.map((server) => ({
            urls: [...server.urls],
            username: server.username,
            credential: server.credential,
        })),
    };
}
