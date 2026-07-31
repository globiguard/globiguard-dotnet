# Changelog

## 0.2.0

- Tightened governed-action execution so only a current, obligation-free
  `ALLOW` decision is executable.
- Added regression coverage for `MODIFY`, queued approvals, and other
  non-executable decisions.

## 0.1.0

- Initial dependency-minimal .NET SDK foundation.
- Added credential helpers, safe request transport, resource clients, governed action helpers, trust webhook verification, bootstrap helpers, and entitlement manifest parsing with pluggable Ed25519 verification.

