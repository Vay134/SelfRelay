import { useEffect, useState } from 'react';

import AccountConsole from './AccountConsole';
import TransferConsole from './TransferConsole';
import { nextWorkspaceView, WORKSPACE_VIEWS, type WorkspaceView } from './workspaceTabs';

function DeviceStatus() {
    const [status, setStatus] = useState<'checking' | 'available' | 'missing'>('checking');

    useEffect(() => {
        let mounted = true;
        void import('./deviceIdentity')
            .then(({ deviceKeyStatus }) => deviceKeyStatus())
            .then((nextStatus) => {
                if (mounted) {
                    setStatus(nextStatus);
                }
            })
            .catch(() => {
                if (mounted) {
                    setStatus('missing');
                }
            });
        return () => {
            mounted = false;
        };
    }, []);

    const copy = {
        available: 'Device key ready',
        missing: 'Device key not found',
        checking: 'Checking device key',
    }[status];

    return (
        <span
            className={'status-chip status-chip-' + status}
            data-testid="device-key-status"
            role="status"
            aria-live="polite"
        >
            <span className="status-dot" aria-hidden="true" />
            {copy}
        </span>
    );
}

function App() {
    const [view, setView] = useState<WorkspaceView>('account');

    return (
        <main className="app-shell">
            <header className="app-header">
                <div>
                    <p className="eyebrow">Private transfer workspace</p>
                    <h1>Secure File Transfer</h1>
                    <p className="app-subtitle">
                        Link your browsers once, then move files directly between trusted devices.
                    </p>
                </div>
                <DeviceStatus />
            </header>

            <nav className="workspace-tabs" aria-label="Workspace sections">
                {WORKSPACE_VIEWS.map((item) => (
                    <button
                        className={
                            'workspace-tab ' + (view === item.id ? 'workspace-tab-active' : '')
                        }
                        key={item.id}
                        type="button"
                        onClick={() => setView(item.id)}
                        aria-current={view === item.id ? 'page' : undefined}
                    >
                        {item.label}
                    </button>
                ))}
            </nav>

            <div className="workspace-content">
                {view === 'account' ? <AccountConsole /> : <TransferConsole />}
            </div>

            <footer className="app-footer">
                <span>Keys stay in this browser.</span>
                <span aria-hidden="true">·</span>
                <span>Transfers are encrypted end to end.</span>
                <span aria-hidden="true">·</span>
                <button
                    className="footer-link"
                    type="button"
                    onClick={() => setView(nextWorkspaceView(view, 'ArrowRight') ?? 'account')}
                >
                    {view === 'account' ? 'Open transfers' : 'Manage devices'}
                </button>
            </footer>
        </main>
    );
}

export default App;
