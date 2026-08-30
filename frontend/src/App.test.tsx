import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { sortDevicesByPresence } from './AccountConsole';
import App, { PrivacyPage } from './App';
import type { AuthenticatedDevice } from './pairingApi';

describe('App', () => {
    it('renders the Relay account surface', () => {
        const page = renderToStaticMarkup(<App />);

        expect(page).toContain('<main');
        expect(page).toContain('Checking this browser session');
        expect(page).toContain('Sign up or log in');
    });

    it('uses one page instead of separate account and transfer tabs', () => {
        const markup = renderToStaticMarkup(<App />);

        expect(markup).not.toContain('Workspace sections');
        expect(markup).not.toContain('workspace-tab');
    });

    it('explains the privacy model', () => {
        const markup = renderToStaticMarkup(<PrivacyPage />);

        expect(markup).toContain('Security architecture');
        expect(markup).toContain('AES-256-GCM');
        expect(markup).toContain('WebRTC');
    });

    it('orders online devices before offline devices', () => {
        const device = (device_id: string, last_seen_at: string): AuthenticatedDevice => ({
            device_id,
            last_seen_at,
            label: device_id,
            status: 'active',
            epoch: 1,
            fingerprint: device_id,
            created_at: last_seen_at,
            revoked_at: null,
            linked_by_device_id: null,
        });
        const offline = device('offline', '2026-08-30T12:00:00Z');
        const online = device('online', '2026-08-29T12:00:00Z');

        expect(sortDevicesByPresence([offline, online], new Set(['online']))).toEqual([
            online,
            offline,
        ]);
    });
});
