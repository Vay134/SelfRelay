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
    const confirmButton = useRef<HTMLButtonElement>(null);

    useEffect(() => {
        confirmButton.current?.focus();
        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Escape' && !busy) {
                onCancel();
            }
        };
        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [busy, onCancel]);

    return (
        <div className="dialog-backdrop" role="presentation">
            <div
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
