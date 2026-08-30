import AccountConsole from './AccountConsole';

export function PrivacyPage() {
    return (
        <section className="privacy-page" aria-labelledby="privacy-title">
            <header className="privacy-heading">
                <h1 id="privacy-title">Security architecture</h1>
            </header>

            <figure className="privacy-diagram" aria-labelledby="connection-overview-title">
                <figcaption className="sr-only" id="connection-overview-title">
                    SelfRelay network architecture
                </figcaption>
                <p className="diagram-lane-label">Encrypted data plane</p>
                <div className="diagram-path">
                    <div className="diagram-node">
                        <span>Sender</span>
                        <strong>Browser A</strong>
                    </div>
                    <div className="diagram-channel">
                        <span>Direct peer-to-peer preferred</span>
                        <strong>WebRTC RTCDataChannel</strong>
                        <code>P-256 ECDH → HKDF-SHA-256 → AES-256-GCM</code>
                        <small>TURN relay fallback when a direct path is unavailable</small>
                    </div>
                    <div className="diagram-node">
                        <span>Receiver</span>
                        <strong>Browser B</strong>
                    </div>
                </div>
            </figure>

            <section className="privacy-section" aria-labelledby="transport-title">
                <h2 id="transport-title">Transport</h2>
                <p>
                    Transfers use a WebRTC <code>RTCDataChannel</code>. ICE prefers a direct
                    peer-to-peer path; short-lived TURN credentials provide a relay fallback when
                    the browsers cannot connect directly.
                </p>
                <p>
                    Presence and WebRTC signalling use the SelfRelay service. File payloads travel
                    only over the negotiated data channel.
                </p>
            </section>

            <section className="privacy-section" aria-labelledby="cryptography-title">
                <h2 id="cryptography-title">Cryptography</h2>
                <dl className="privacy-spec">
                    <div>
                        <dt>Key agreement</dt>
                        <dd>
                            Ephemeral P-256 ECDH keys are generated for each transfer. The shared
                            secret is expanded with HKDF-SHA-256.
                        </dd>
                    </div>
                    <div>
                        <dt>Payload encryption</dt>
                        <dd>
                            Independent 256-bit send and receive keys encrypt every protocol frame
                            with AES-256-GCM and a 128-bit authentication tag.
                        </dd>
                    </div>
                    <div>
                        <dt>Device authentication</dt>
                        <dd>
                            P-256 ECDSA signatures bind each handshake and file completion to a
                            trusted device. Private device keys are non-exportable browser{' '}
                            <code>CryptoKey</code> objects stored in IndexedDB.
                        </dd>
                    </div>
                    <div>
                        <dt>File integrity</dt>
                        <dd>
                            The receiver checks the complete SHA-256 digest, signed completion
                            record, byte count, and transfer transcript before returning a verified
                            receipt.
                        </dd>
                    </div>
                </dl>
            </section>

            <section className="privacy-section privacy-boundary" aria-labelledby="boundary-title">
                <h2 id="boundary-title">Service boundary</h2>
                <p>
                    SelfRelay coordinates accounts, device presence, signalling, and TURN access. It
                    does not receive file plaintext or the per-transfer encryption keys. A TURN
                    relay can forward encrypted frames but cannot decrypt their contents.
                </p>
            </section>
        </section>
    );
}

function App() {
    const onPrivacyPage = typeof window !== 'undefined' && window.location.pathname === '/privacy';

    return (
        <main className="app-shell">
            <header className="site-header">
                <a className="site-brand" href="/">
                    <img className="site-logo" src="/logo.svg" alt="" />
                    SelfRelay
                </a>
                <a className="privacy-link" href={onPrivacyPage ? '/' : '/privacy'}>
                    {onPrivacyPage ? 'Back home' : 'Privacy'}
                </a>
            </header>
            {onPrivacyPage ? (
                <PrivacyPage />
            ) : (
                <>
                    <AccountConsole />
                    <section className="home-guide" aria-labelledby="guide-title">
                        <p className="section-kicker">How it works</p>
                        <h2 className="sr-only" id="guide-title">
                            Transfer a file in three steps
                        </h2>
                        <ol className="guide-steps">
                            <li>
                                <span>01</span>
                                <div>
                                    <strong>Sign up or log in</strong>
                                    <p>Use your email address or a device code.</p>
                                </div>
                            </li>
                            <li>
                                <span>02</span>
                                <div>
                                    <strong>Transfer files</strong>
                                    <p>Choose another connected device.</p>
                                </div>
                            </li>
                            <li>
                                <span>03</span>
                                <div>
                                    <strong>Done!</strong>
                                    <p>The receiving device verifies the file.</p>
                                </div>
                            </li>
                        </ol>
                    </section>
                </>
            )}
        </main>
    );
}

export default App;
