# Security Policy

Report suspected vulnerabilities privately through GitHub security advisories for `globiguard/globiguard-dotnet`.

## Supported versions

The `0.x` series receives security fixes while the SDK surface is stabilizing.

## Security expectations

- Do not log secret keys, webhook secrets, raw entitlement signing keys, or raw webhook bodies that may contain sensitive data.
- Always verify trust webhooks against the exact raw request body bytes.
- Use `sandbox` for tests and `live` only for production credentials issued by the GlobiGuard app.
- Keep runtime dependencies at zero unless a reviewed security need outweighs the supply-chain cost.

