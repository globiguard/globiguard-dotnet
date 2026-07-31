# Changelog

## 0.2.1

- Fixed request-path validation on Linux so valid root-relative API paths are
  accepted while URLs, traversal, encoded separators, queries, and fragments
  remain rejected.
- Updated the SDK identification header to the published package version.

## 0.2.0

- Tightened governed-action execution so only a current, obligation-free
  `ALLOW` decision is executable.
- Added regression coverage for `MODIFY`, queued approvals, and other
  non-executable decisions.

## 0.1.0

- Initial dependency-minimal .NET SDK foundation.
- Added credential helpers, safe request transport, resource clients, governed action helpers, trust webhook verification, bootstrap helpers, and entitlement manifest parsing with pluggable Ed25519 verification.

