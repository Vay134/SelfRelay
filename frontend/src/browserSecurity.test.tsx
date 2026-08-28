import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';

import { apiRequest, ApiError, clearApiSession } from './pairingApi';
import { sanitizeFileName, sanitizeMediaType } from './fileTransfer';

const hostileText = '"/><svg/onload=alert(1)><script>alert(2)</script>';

function UntrustedTextFixture({
    label,
    fileName,
    mediaType,
    error,
}: {
    label: string;
    fileName: string;
    mediaType: string;
    error: string;
}) {
    return (
        <section>
            <span>{label}</span>
            <strong>{fileName}</strong>
            <code>{mediaType}</code>
            <p role="alert">{error}</p>
        </section>
    );
}

function renderUntrustedText(value: string): string {
    return renderToStaticMarkup(
        <UntrustedTextFixture
            label={value}
            fileName={value}
            mediaType={value}
            error={value}
        />,
    );
}

function expectNoExecutableMarkup(markup: string): void {
    expect(markup).not.toMatch(/<\s*(?:script|svg|img|iframe|object|style)\b/iu);
    const tags = markup.match(/<[^>]+>/gu) ?? [];
    expect(tags.join(' ')).not.toMatch(/\bon(?:error|load|focus)\s*=/iu);
}

afterEach(() => {
    clearApiSession();
    vi.restoreAllMocks();
});

describe('browser untrusted-content boundaries', () => {
    it('renders hostile labels, file names, MIME hints, and errors as text', () => {
        const markup = renderUntrustedText(hostileText);

        expectNoExecutableMarkup(markup);
        expect(markup).toContain('&lt;svg/onload=alert(1)&gt;');
        expect(markup).toContain('&lt;script&gt;alert(2)&lt;/script&gt;');
    });

    it('normalizes hostile file names before they reach a download', () => {
        const fileName = sanitizeFileName(hostileText);

        expect(fileName).not.toMatch(/[<>]/u);
        expectNoExecutableMarkup(renderUntrustedText(fileName));
        expect(fileName).toBeTruthy();
    });

    it('falls back for MIME values outside the simple token grammar', () => {
        expect(sanitizeMediaType('text/plain')).toBe('text/plain');
        expect(sanitizeMediaType('text/html;charset=utf-8')).toBe('application/octet-stream');
        expect(sanitizeMediaType(hostileText)).toBe('application/octet-stream');
    });

    it('keeps server error text plain when the API returns markup-looking detail', async () => {
        vi.spyOn(globalThis, 'fetch').mockResolvedValue(
            new Response(JSON.stringify({ detail: hostileText }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' },
            }),
        );

        let caught: unknown;
        try {
            await apiRequest('/hostile-input-test');
        } catch (error) {
            caught = error;
        }

        expect(caught).toBeInstanceOf(ApiError);
        expect((caught as ApiError).detail).toBe(hostileText);
        expectNoExecutableMarkup(renderUntrustedText((caught as ApiError).detail));
    });
});
