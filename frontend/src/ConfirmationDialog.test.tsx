import { describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';

import ConfirmationDialog from './ConfirmationDialog';

describe('ConfirmationDialog', () => {
    it('renders confirmation copy as text and exposes dialog semantics', () => {
        const markup = renderToStaticMarkup(
            <ConfirmationDialog
                title={'Approve <script>alert(1)</script>'}
                description={'A filename & label should stay text.'}
                confirmLabel="Approve browser"
                onCancel={vi.fn()}
                onConfirm={vi.fn()}
            />,
        );

        expect(markup).toContain('role="dialog"');
        expect(markup).toContain('aria-modal="true"');
        expect(markup).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
        expect(markup).not.toContain('<script>alert(1)</script>');
    });
});
