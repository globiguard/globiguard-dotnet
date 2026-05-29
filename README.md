# globiguard-dotnet

Official dependency-minimal .NET SDK for GlobiGuard.

The package uses only the .NET base class library at runtime. It mirrors the TypeScript, Python, Go, and JavaScript SDK contracts for auth headers, safe request paths, governed actions, install bootstrap, trust webhooks, and entitlement manifests.

## Install

```bash
dotnet add package GlobiGuard
```

Until the first NuGet release, reference `src/GlobiGuard/GlobiGuard.csproj` directly.

## Server client

```csharp
using GlobiGuard;

var client = GlobiGuardClient.CreateServer(new ClientOptions(
    EnvironmentName.Sandbox,
    new Dictionary<string, string> { ["controlPlane"] = "https://api.globiguard.com" },
    Credential.Secret("proj_example", "ggsk_example_replace_me", EnvironmentName.Sandbox)
));

var decision = await client.GovernedActions.AuthorizeActionOrThrowAsync(new Dictionary<string, object?>
{
    ["actionType"] = "refund",
    ["actor"] = new Dictionary<string, object?> { ["id"] = "user_123" },
    ["target"] = new Dictionary<string, object?> { ["id"] = "order_456" }
});
```

## Webhooks

Pass the exact raw request body bytes received by ASP.NET. Do not parse and re-serialize JSON before verification.

```csharp
var result = TrustWebhookVerifier.Verify(headers, rawBody, "whsec_example_replace_me");
if (!result.Ok) throw new InvalidOperationException(result.Error);
```

## Entitlement manifests

.NET does not currently expose a stable BCL Ed25519 verifier across all supported targets, so the SDK keeps zero runtime dependencies and accepts an explicit signature verifier delegate for offline entitlement verification. Hosted runtime checks and schema/timestamp validation remain built in.

## Development

```bash
dotnet build
dotnet run --project tests/GlobiGuard.Tests
dotnet pack src/GlobiGuard -c Release
```
