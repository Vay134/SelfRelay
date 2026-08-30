import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import App from './App';
import { nextWorkspaceView } from './workspaceTabs';

describe('App', () => {
    it('renders the frontend health page', () => {
        const page = renderToStaticMarkup(<App />);

        expect(page).toContain('<main');
        expect(page).toContain('Secure File Transfer');
    });

    it('renders the workspace as an accessible tablist with linked panels', () => {
        const markup = renderToStaticMarkup(<App />);

        expect(markup).toContain('aria-label="Workspace sections"');
        expect(markup.match(/class="workspace-tab /gu)).toHaveLength(2);
        expect(markup).toContain('Transfer devices');
    });

    it('moves through workspace tabs with wraparound and Home/End support', () => {
        expect(nextWorkspaceView('account', 'ArrowLeft')).toBe('transfers');
        expect(nextWorkspaceView('transfers', 'ArrowRight')).toBe('account');
        expect(nextWorkspaceView('account', 'Home')).toBe('account');
        expect(nextWorkspaceView('transfers', 'End')).toBe('transfers');
        expect(nextWorkspaceView('account', 'Enter')).toBeNull();
    });
});
