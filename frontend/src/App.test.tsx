import { describe, expect, it } from 'vitest';

import App from './App';

describe('App', () => {
    it('renders the frontend health page', () => {
        const page = App();

        expect(page.type).toBe('main');
        expect(page.props.className).toBe('health-page');
    });
});
