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
            </section>
        </main>
    )
}

export default App
