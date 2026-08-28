import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import App from './App';
import { nextWorkspaceView } from './workspaceTabs';

describe('App', () => {
    it('renders the frontend health page', () => {
        const page = App();

        expect(page.type).toBe('main');
        expect(page.props.className).toBe('health-page');
    });

    it('renders the workspace as an accessible tablist with linked panels', () => {
        const markup = renderToStaticMarkup(<App />);

        expect(markup).toContain('role="tablist"');
        expect(markup.match(/role="tab"/gu)).toHaveLength(4);
        expect(markup).toContain('aria-selected="true"');
        expect(markup).toContain('aria-controls="workspace-panel-account"');
        expect(markup).toContain('role="tabpanel"');
        expect(markup).toContain('aria-labelledby="workspace-tab-account"');
    });

    it('moves through workspace tabs with wraparound and Home/End support', () => {
        expect(nextWorkspaceView('account', 'ArrowLeft')).toBe('transfers');
        expect(nextWorkspaceView('transfers', 'ArrowRight')).toBe('account');
        expect(nextWorkspaceView('new-browser', 'Home')).toBe('account');
        expect(nextWorkspaceView('trusted-device', 'End')).toBe('transfers');
        expect(nextWorkspaceView('account', 'Enter')).toBeNull();
    });
});
