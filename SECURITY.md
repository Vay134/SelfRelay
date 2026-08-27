# Security policy

## Project status

This project is under development and has not received a professional security audit. Do not use it to transfer sensitive or irreplaceable files until a release is explicitly marked as suitable for public testing.

## Reporting a vulnerability

Please do not publish exploit details in a public issue. During development, report the problem privately to the repository owner. A dedicated security contact or GitHub private vulnerability reporting link will be added before the public deployment.

Include the affected commit or release, the steps needed to reproduce the issue, its likely impact, and any proof of concept that can be shared safely. Remove real credentials, personal data, and file contents from the report.

## Expected response

There is no service-level agreement during development. The repository owner will acknowledge a report, reproduce it where possible, and publish a fix or mitigation before disclosing technical details.

## Scope

Reports are particularly useful when they concern:

- account takeover, session theft, or device-pairing bypasses
- leakage or substitution of device public keys
- failures in handshake authentication, nonce handling, or file encryption
- cross-account signaling or insecure direct object references
- cross-site scripting, cross-site request forgery, or unsafe CORS behavior
- TURN credential abuse or bypasses of rate limits
- secrets committed to the repository or exposed to the browser
- file plaintext reaching an application server

The project cannot protect a file after the recipient saves or opens it. It also cannot protect an endpoint whose browser, extensions, or operating system is compromised. The web host is trusted to serve the documented client code.

## Handling test data

Use synthetic files and test accounts. Never commit API keys, SMTP credentials, Supabase secret keys, database passwords, session tokens, or private device keys. Development-only authentication fakes must refuse to run in a production environment.

