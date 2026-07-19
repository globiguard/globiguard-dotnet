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
    ["context"] = new Dictionary<string, object?>
    {
        ["actionType"] = "refund.create",
        ["destination"] = new Dictionary<string, object?>
        {
            ["type"] = "custom",
            ["name"] = "payments-production"
        },
        ["dataClasses"] = new[] { "CONFIDENTIAL" },
        ["actor"] = new Dictionary<string, object?>
        {
            ["id"] = "support-agent-123",
            ["type"] = "agent"
        },
        ["purpose"] = "Resolve an approved customer escalation",
        ["correlationId"] = "case_456",
        ["idempotencyKey"] = "case_456:refund:v1"
    }
});
```

`AuthorizeActionOrThrowAsync` returns only `ALLOW` or `MODIFY`. It raises
`GlobiguardAuthorityException` for `QUEUE` and `BLOCK`, keeping the downstream
business action stopped. Evidence summaries and incident history are available
through `client.Audit.GetEvidencePackageSummaryAsync(...)` and
`client.Audit.GetIncidentReplayAsync(...)`.

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
