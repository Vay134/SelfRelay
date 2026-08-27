import { useEffect, useState } from 'react';

import { deviceKeyStatus } from './deviceIdentity';

function DeviceStatus() {
    const [status, setStatus] = useState<'checking' | 'available' | 'missing'>('checking');

    useEffect(() => {
        let mounted = true;
        void deviceKeyStatus()
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

    if (status === 'available') {
        return (
            <p className="device-status device-status-ok" data-testid="device-key-status">
                Device key ready in this browser.
            </p>
        );
    }
    if (status === 'missing') {
        return (
            <p className="device-status device-status-warning" data-testid="device-key-status">
                No device key was found. If site data was cleared, recover or pair this browser to
                continue.
            </p>
        );
    }
    return (
        <p className="device-status" data-testid="device-key-status">
            Checking this browser for its device key…
        </p>
    );
}

function App() {
    return (
        <main className="health-page">
            <section className="status-card" aria-labelledby="page-title">
                <p className="eyebrow">Phase 0 scaffold</p>
                <h1 id="page-title">E2E Secure File Transfer System</h1>
                <p className="status-message">The frontend is running.</p>
                <dl className="status-list">
                    <div>
                        <dt>Service</dt>
                        <dd>frontend</dd>
                    </div>
                    <div>
                        <dt>Status</dt>
                        <dd className="status-ok">ok</dd>
                    </div>
                </dl>
                <DeviceStatus />
            </section>
        </main>
    );
}

export default App;
