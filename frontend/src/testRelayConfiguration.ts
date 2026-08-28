import type { TurnCredentials } from './transferApi';
import { rtcConfigurationFromTurnCredentials } from './rtcConfiguration';

/** Test-only configuration for forced-relay integration tests; do not import from UI code. */
export function createRelayOnlyRtcConfiguration(credentials: TurnCredentials): RTCConfiguration {
    return {
        ...rtcConfigurationFromTurnCredentials(credentials),
        iceTransportPolicy: 'relay',
    };
}
