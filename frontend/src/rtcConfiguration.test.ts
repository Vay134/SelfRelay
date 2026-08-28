import { describe, expect, it } from 'vitest';

import type { TurnCredentials } from './transferApi';
import { rtcConfigurationFromTurnCredentials } from './rtcConfiguration';
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

    it('provides relay-only configuration only through the test support module', () => {
        expect(createRelayOnlyRtcConfiguration(credentials)).toEqual({
            iceServers: credentials.ice_servers,
            iceTransportPolicy: 'relay',
        });
    });
});
