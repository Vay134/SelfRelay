import { describe, expect, it } from 'vitest';

import type { TurnCredentials } from './transferApi';
import { relayOnlyTestEnabled, rtcConfigurationFromTurnCredentials } from './rtcConfiguration';
import { createRelayOnlyRtcConfiguration } from './testRelayConfiguration';

const credentials: TurnCredentials = {
    ice_servers: [
        {
            urls: ['stun:turn.test.invalid', 'turn:turn.test.invalid?transport=udp'],
            username: 'turn-user',
            credential: 'turn-credential',
        },
    ],
    expires_at: 1_700_000_120_000,
};

describe('RTC configuration', () => {
    it('keeps the normal configuration direct-first', () => {
        expect(rtcConfigurationFromTurnCredentials(credentials)).toEqual({
            iceServers: credentials.ice_servers,
        });
    });

    it('uses relay-only ICE only when the test option is enabled', () => {
        expect(rtcConfigurationFromTurnCredentials(credentials, { relayOnly: true })).toEqual({
            iceServers: credentials.ice_servers,
            iceTransportPolicy: 'relay',
        });
    });

    it('enables relay-only mode only for the explicit test environment value', () => {
        expect(relayOnlyTestEnabled()).toBe(false);
        expect(relayOnlyTestEnabled({ VITE_FORCE_RELAY_FOR_TESTS: 'true' })).toBe(true);
        expect(relayOnlyTestEnabled({ VITE_FORCE_RELAY_FOR_TESTS: 'TRUE' })).toBe(false);
    });

    it('keeps the test support configuration relay-only', () => {
        expect(createRelayOnlyRtcConfiguration(credentials)).toEqual({
            iceServers: credentials.ice_servers,
            iceTransportPolicy: 'relay',
        });
    });
});
