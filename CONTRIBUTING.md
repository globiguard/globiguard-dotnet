# Contributing

GlobiGuard .NET SDK changes should keep the runtime dependency surface at zero unless a security review accepts a specific exception.

## Validate locally

```bash
dotnet build
dotnet run --project tests/GlobiGuard.Tests
dotnet pack src/GlobiGuard -c Release
```

Examples must use placeholder secrets only and webhook handlers must pass raw request body bytes into verification.

