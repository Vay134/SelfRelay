import { useEffect, useRef } from 'react';

export type ConfirmationDialogProps = {
    title: string;
    description: string;
    confirmLabel: string;
    danger?: boolean;
    busy?: boolean;
    onCancel: () => void;
    onConfirm: () => void;
};

function ConfirmationDialog({
    title,
    description,
    confirmLabel,
    danger = false,
    busy = false,
    onCancel,
    onConfirm,
}: ConfirmationDialogProps) {
    const dialog = useRef<HTMLDivElement>(null);
    const confirmButton = useRef<HTMLButtonElement>(null);
    const previouslyFocused = useRef<HTMLElement | null>(null);

    useEffect(() => {
        previouslyFocused.current =
            document.activeElement instanceof HTMLElement ? document.activeElement : null;
        confirmButton.current?.focus();
        return () => {
            if (previouslyFocused.current?.isConnected) {
                previouslyFocused.current.focus();
            }
        };
    }, []);

    useEffect(() => {
        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Escape' && !busy) {
                event.preventDefault();
                onCancel();
                return;
            }
            if (event.key !== 'Tab') {
                return;
            }
            const focusable = dialog.current?.querySelectorAll<HTMLElement>(
                'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
            );
            if (!focusable?.length) {
                event.preventDefault();
                return;
            }
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            const active = document.activeElement;
            if (!dialog.current?.contains(active)) {
                event.preventDefault();
                first.focus();
            } else if (event.shiftKey && active === first) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && active === last) {
                event.preventDefault();
                first.focus();
            }
        };
        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [busy, onCancel]);

    return (
        <div className="dialog-backdrop" role="presentation">
            <div
                ref={dialog}
                className="confirm-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="confirmation-dialog-title"
                aria-describedby="confirmation-dialog-description"
            >
                <p className="section-kicker">Please confirm</p>
                <h2 id="confirmation-dialog-title">{title}</h2>
                <p id="confirmation-dialog-description">{description}</p>
                <div className="request-actions">
                    <button
                        className="button button-secondary"
                        type="button"
                        onClick={onCancel}
                        disabled={busy}
                    >
                        Cancel
                    </button>
                    <button
                        ref={confirmButton}
                        className={`button ${danger ? 'button-danger' : 'button-primary'}`}
                        type="button"
                        onClick={onConfirm}
                        disabled={busy}
                    >
                        {busy ? 'Working…' : confirmLabel}
                    </button>
                </div>
            </div>
        </div>
    );
}

export default ConfirmationDialog;
