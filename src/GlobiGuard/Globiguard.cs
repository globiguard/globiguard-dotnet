using System.Collections.ObjectModel;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace GlobiGuard;

public static class EnvironmentName
{
    public const string Local = "local";
    public const string Sandbox = "sandbox";
    public const string Live = "live";

    public static bool IsValid(string value) => value is Local or Sandbox or Live;
}

public sealed record Credential(string Kind, string? ProjectId, string? Token, string Environment)
{
    public static Credential Secret(string projectId, string token, string environment) => new("secret", projectId, token, environment);
    public static Credential Publishable(string projectId, string token, string environment) => new("publishable", projectId, token, environment);
    public static Credential Local(string? token = null) => new("local", null, token, EnvironmentName.Local);
}

public sealed record ClientOptions(string Environment, IReadOnlyDictionary<string, string> Services, Credential Credential, HttpClient? HttpClient = null);

public sealed class GlobiguardAuthorityException : Exception
{
    public string Kind { get; }
    public string? AuthorizationId { get; }
    public string? QueueEntryId { get; }

    public GlobiguardAuthorityException(string kind, string message, string? authorizationId = null, string? queueEntryId = null)
        : base(message)
    {
        Kind = kind;
        AuthorizationId = authorizationId;
        QueueEntryId = queueEntryId;
    }
}

public sealed class GlobiGuardClient
{
    private readonly Transport _transport;
    public ActionsClient Actions { get; }
    public AuditClient Audit { get; }
    public ResourceClient Installs { get; }
    public ResourceClient Orgs { get; }
    public ResourceClient Policies { get; }
    public QueueClient Queue { get; }
    public ResourceClient Workflows { get; }
    public GovernedActionsClient GovernedActions { get; }

    private GlobiGuardClient(Transport transport, bool readOnly)
    {
        _transport = transport;
        Actions = new ActionsClient(transport, readOnly);
        Audit = new AuditClient(transport, readOnly);
        Installs = new ResourceClient(transport, "/v1/installs", readOnly);
        Orgs = new ResourceClient(transport, "/v1/orgs", readOnly);
        Policies = new ResourceClient(transport, "/v1/policies", readOnly);
        Queue = new QueueClient(transport, readOnly);
        Workflows = new ResourceClient(transport, "/v1/workflows", readOnly);
        GovernedActions = new GovernedActionsClient(Actions, Audit, Queue);
    }

    public static GlobiGuardClient CreateServer(ClientOptions options)
    {
        if (options.Credential.Kind == "publishable") throw new ArgumentException("Server clients require secret or local credentials.");
        return new GlobiGuardClient(new Transport(options), false);
    }

    public static GlobiGuardClient CreateBrowser(ClientOptions options)
    {
        if (options.Credential.Kind == "secret") throw new ArgumentException("Browser clients cannot use secret credentials.");
        return new GlobiGuardClient(new Transport(options), true);
    }
}

public sealed class Transport
{
    private static readonly HashSet<string> ReservedHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "x-globiguard-project-id", "x-globiguard-secret-key", "x-globiguard-publishable-key",
        "x-globiguard-local-mode", "x-globiguard-local-token", "x-globiguard-client", "x-globiguard-environment"
    };

    private readonly ClientOptions _options;
    private readonly HttpClient _http;

    public Transport(ClientOptions options)
    {
        if (!EnvironmentName.IsValid(options.Environment)) throw new ArgumentException("Environment must be local, sandbox, or live.");
        if (options.Credential.Environment != options.Environment) throw new ArgumentException("Credential environment must match client environment.");
        if (!options.Services.TryGetValue("controlPlane", out var baseUrl)) throw new ArgumentException("services.controlPlane is required.");
        var baseUri = new Uri(baseUrl, UriKind.Absolute);
        if (options.Environment != EnvironmentName.Local && baseUri.Scheme != "https") throw new ArgumentException("HTTPS is required outside local.");
        if (options.Credential.Kind == "local" && !IsLoopback(baseUri)) throw new ArgumentException("Local credentials require localhost or loopback URLs.");
        _options = options;
        _http = options.HttpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    public async Task<JsonElement> RequestAsync(
        HttpMethod method,
        string path,
        object? body = null,
        IReadOnlyDictionary<string, string>? headers = null,
        CancellationToken cancellationToken = default,
        IReadOnlyDictionary<string, string?>? query = null)
    {
        ValidatePath(path);
        var uriBuilder = new UriBuilder(new Uri(new Uri(_options.Services["controlPlane"].TrimEnd('/') + "/"), path.TrimStart('/')));
        if (query is not null)
        {
            uriBuilder.Query = string.Join("&", query
                .Where(entry => !string.IsNullOrWhiteSpace(entry.Value))
                .Select(entry => $"{Uri.EscapeDataString(entry.Key)}={Uri.EscapeDataString(entry.Value!)}"));
        }
        var uri = uriBuilder.Uri;
        using var request = new HttpRequestMessage(method, uri);
        foreach (var header in AuthHeaders())
        {
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        if (headers is not null)
        {
            foreach (var header in headers)
            {
                if (ReservedHeaders.Contains(header.Key)) throw new ArgumentException($"Reserved GlobiGuard header cannot be overridden: {header.Key}");
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw new HttpRequestException($"GlobiGuard request failed with {(int)response.StatusCode}: {text}");
        if (string.IsNullOrWhiteSpace(text)) return JsonDocument.Parse("{}").RootElement.Clone();
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    private IReadOnlyDictionary<string, string> AuthHeaders()
    {
        var headers = new Dictionary<string, string>
        {
            ["x-globiguard-client"] = "globiguard-dotnet/0.1.0",
            ["x-globiguard-environment"] = _options.Environment
        };
        if (_options.Credential.Kind == "local")
        {
            headers["x-globiguard-local-mode"] = "true";
            if (!string.IsNullOrEmpty(_options.Credential.Token)) headers["x-globiguard-local-token"] = _options.Credential.Token!;
        }
        else
        {
            headers["x-globiguard-project-id"] = _options.Credential.ProjectId ?? throw new ArgumentException("Project id is required.");
            headers[_options.Credential.Kind == "secret" ? "x-globiguard-secret-key" : "x-globiguard-publishable-key"] = _options.Credential.Token ?? throw new ArgumentException("Credential token is required.");
        }
        return new ReadOnlyDictionary<string, string>(headers);
    }

    private static bool IsLoopback(Uri uri) => uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);

    public static void ValidatePath(string path)
    {
        if (!path.StartsWith('/')) throw new ArgumentException("Request path must start with /.");
        if (path.StartsWith("//") || path.Contains("//") || path.Contains('\\') || path.Contains('?') || path.Contains('#')) throw new ArgumentException("Unsafe request path.");
        if (Uri.TryCreate(path, UriKind.Absolute, out _)) throw new ArgumentException("Absolute request paths are not allowed.");
        if (Regex.IsMatch(path, "%(?![0-9A-Fa-f]{2})")) throw new ArgumentException("Invalid percent encoding.");
        if (path.Split('/').Any(segment =>
        {
            var decoded = Uri.UnescapeDataString(segment);
            return decoded is "." or ".." || decoded.Contains('/') || decoded.Contains('\\');
        })) throw new ArgumentException("Encoded separators and dot segments are not allowed.");
    }
}

public sealed class ResourceClient
{
    private readonly Transport _transport;
    private readonly string _basePath;
    private readonly bool _readOnly;
    public ResourceClient(Transport transport, string basePath, bool readOnly = false) { _transport = transport; _basePath = basePath; _readOnly = readOnly; }
    public Task<JsonElement> ListAsync(CancellationToken cancellationToken = default) => _transport.RequestAsync(HttpMethod.Get, _basePath, cancellationToken: cancellationToken);
    public Task<JsonElement> GetAsync(string id, CancellationToken cancellationToken = default) => _transport.RequestAsync(HttpMethod.Get, $"{_basePath}/{Uri.EscapeDataString(id)}", cancellationToken: cancellationToken);
    public Task<JsonElement> CreateAsync(object body, CancellationToken cancellationToken = default)
    {
        RequireWrite();
        return _transport.RequestAsync(HttpMethod.Post, _basePath, body, cancellationToken: cancellationToken);
    }
    public Task<JsonElement> PostAsync(string suffix, object body, CancellationToken cancellationToken = default)
    {
        RequireWrite();
        return _transport.RequestAsync(HttpMethod.Post, $"{_basePath}/{suffix.TrimStart('/')}", body, cancellationToken: cancellationToken);
    }
    private void RequireWrite()
    {
        if (_readOnly) throw new ArgumentException("Resource writes require a server client.");
    }
}

public sealed class ActionsClient
{
    private readonly Transport _transport;
    private readonly bool _readOnly;

    public ActionsClient(Transport transport, bool readOnly)
    {
        _transport = transport;
        _readOnly = readOnly;
    }

    public Task<JsonElement> GetAuthorizationAsync(string authorizationId, CancellationToken cancellationToken = default) =>
        _transport.RequestAsync(HttpMethod.Get, $"/v1/actions/authorizations/{Uri.EscapeDataString(authorizationId)}", cancellationToken: cancellationToken);

    public Task<JsonElement> GetApprovalAsync(string approvalId, CancellationToken cancellationToken = default) =>
        _transport.RequestAsync(HttpMethod.Get, $"/v1/actions/approvals/{Uri.EscapeDataString(approvalId)}", cancellationToken: cancellationToken);

    public Task<JsonElement> ListEvidenceAsync(
        string? authorizationId = null,
        string? approvalId = null,
        string? workflowRunId = null,
        CancellationToken cancellationToken = default) =>
        _transport.RequestAsync(
            HttpMethod.Get,
            "/v1/actions/evidence",
            cancellationToken: cancellationToken,
            query: new Dictionary<string, string?>
            {
                ["authorizationId"] = authorizationId,
                ["approvalId"] = approvalId,
                ["workflowRunId"] = workflowRunId
            });

    public Task<JsonElement> GetEvidenceAsync(string evidenceId, CancellationToken cancellationToken = default) =>
        _transport.RequestAsync(HttpMethod.Get, $"/v1/actions/evidence/{Uri.EscapeDataString(evidenceId)}", cancellationToken: cancellationToken);

    public Task<JsonElement> AuthorizeAsync(object request, CancellationToken cancellationToken = default)
    {
        RequireWrite();
        return _transport.RequestAsync(HttpMethod.Post, "/v1/actions/authorize", request, cancellationToken: cancellationToken);
    }

    public Task<JsonElement> CreateApprovalAsync(object request, CancellationToken cancellationToken = default)
    {
        RequireWrite();
        return _transport.RequestAsync(HttpMethod.Post, "/v1/actions/approvals", request, cancellationToken: cancellationToken);
    }

    private void RequireWrite()
    {
        if (_readOnly) throw new ArgumentException("Action writes require a server client.");
    }
}

public sealed class AuditClient
{
    private readonly Transport _transport;
    private readonly bool _readOnly;

    public AuditClient(Transport transport, bool readOnly)
    {
        _transport = transport;
        _readOnly = readOnly;
    }

    public Task<JsonElement> ListAsync(
        string? from = null,
        string? to = null,
        string? decision = null,
        string? workflowRunId = null,
        int? page = null,
        int? limit = null,
        CancellationToken cancellationToken = default) =>
        _transport.RequestAsync(
            HttpMethod.Get,
            "/v1/audit",
            cancellationToken: cancellationToken,
            query: new Dictionary<string, string?>
            {
                ["from"] = from,
                ["to"] = to,
                ["decision"] = decision,
                ["workflowRunId"] = workflowRunId,
                ["page"] = page?.ToString(),
                ["limit"] = limit?.ToString()
            });

    public Task<JsonElement> GetAsync(string auditEventId, CancellationToken cancellationToken = default) =>
        _transport.RequestAsync(HttpMethod.Get, $"/v1/audit/{Uri.EscapeDataString(auditEventId)}", cancellationToken: cancellationToken);

    public Task<JsonElement> ExportAsync(object? request = null, CancellationToken cancellationToken = default)
    {
        if (_readOnly) throw new ArgumentException("Evidence export requires a server client.");
        return _transport.RequestAsync(HttpMethod.Post, "/v1/audit/export", request ?? new Dictionary<string, object>(), cancellationToken: cancellationToken);
    }

    public Task<JsonElement> GetEvidencePackageSummaryAsync(string evidencePackageId, CancellationToken cancellationToken = default) =>
        _transport.RequestAsync(HttpMethod.Get, $"/v1/audit/evidence-packages/{Uri.EscapeDataString(evidencePackageId)}/summary", cancellationToken: cancellationToken);

    public Task<JsonElement> GetIncidentReplayAsync(string lookupKind, string lookupId, CancellationToken cancellationToken = default)
    {
        var allowed = new HashSet<string> { "workflowRunId", "correlationId", "queueEntryId", "auditEventId", "authorizationId" };
        if (!allowed.Contains(lookupKind)) throw new ArgumentException("Unsupported incident replay lookup kind.");
        return _transport.RequestAsync(
            HttpMethod.Get,
            "/v1/audit/incident-replay",
            cancellationToken: cancellationToken,
            query: new Dictionary<string, string?> { [lookupKind] = lookupId });
    }
}

public sealed class QueueClient
{
    private readonly Transport _transport;
    private readonly bool _readOnly;

    public QueueClient(Transport transport, bool readOnly)
    {
        _transport = transport;
        _readOnly = readOnly;
    }

    public Task<JsonElement> ListAsync(string? status = null, CancellationToken cancellationToken = default) =>
        _transport.RequestAsync(
            HttpMethod.Get,
            "/v1/queue",
            cancellationToken: cancellationToken,
            query: new Dictionary<string, string?> { ["status"] = status });

    public Task<JsonElement> GetAsync(string queueEntryId, CancellationToken cancellationToken = default) =>
        _transport.RequestAsync(HttpMethod.Get, $"/v1/queue/{Uri.EscapeDataString(queueEntryId)}", cancellationToken: cancellationToken);

    public Task<JsonElement> ReviewAsync(string queueEntryId, string action, object? request = null, CancellationToken cancellationToken = default)
    {
        if (_readOnly) throw new ArgumentException("Queue review requires a server client.");
        var allowed = new HashSet<string> { "approve", "reject", "modify", "escalate", "resume" };
        if (!allowed.Contains(action)) throw new ArgumentException("Unsupported queue review action.");
        return _transport.RequestAsync(
            HttpMethod.Post,
            $"/v1/queue/{Uri.EscapeDataString(queueEntryId)}/{action}",
            request ?? new Dictionary<string, object>(),
            cancellationToken: cancellationToken);
    }
}

public sealed class GovernedActionsClient
{
    public static readonly TimeSpan MaxExecutionAuthorizationTtl = TimeSpan.FromMinutes(5);

    private readonly ActionsClient _actions;
    private readonly AuditClient _audit;
    private readonly QueueClient _queue;

    public GovernedActionsClient(ActionsClient actions, AuditClient audit, QueueClient queue)
    {
        _actions = actions;
        _audit = audit;
        _queue = queue;
    }

    public Task<JsonElement> AuthorizeActionAsync(object body, CancellationToken cancellationToken = default) =>
        _actions.AuthorizeAsync(body, cancellationToken);

    public async Task<JsonElement> AuthorizeActionOrThrowAsync(object body, CancellationToken cancellationToken = default)
    {
        var result = await _actions.AuthorizeAsync(body, cancellationToken).ConfigureAwait(false);
        AssertExecutableAuthorization(result, IsDryRun(body));
        return result;
    }

    public static void AssertExecutableAuthorization(JsonElement result, bool simulation = false, DateTimeOffset? now = null)
    {
        var decision = result.TryGetProperty("decision", out var decisionValue) ? decisionValue.GetString() : null;
        var authorizationId = result.TryGetProperty("authorizationId", out var authorizationValue) ? authorizationValue.GetString() : null;
        var queueEntryId = result.TryGetProperty("queueEntryId", out var queueValue) && queueValue.ValueKind == JsonValueKind.String ? queueValue.GetString() : null;
        switch (decision)
        {
            case "BLOCK":
                throw new GlobiguardAuthorityException("POLICY_BLOCKED", "GlobiGuard blocked the governed action.", authorizationId, queueEntryId);
            case "QUEUE":
                throw new GlobiguardAuthorityException("QUEUED_FOR_REVIEW", "GlobiGuard queued the governed action for review; do not perform the downstream business action yet.", authorizationId, queueEntryId);
            case "MODIFY":
                throw new GlobiguardAuthorityException("STEP_UP_REQUIRED", "Apply modifications through a typed handler and reauthorize the exact resulting action before execution.", authorizationId, queueEntryId);
            case "ALLOW":
                break;
            default:
                throw new GlobiguardAuthorityException("CONTROL_PLANE_UNAVAILABLE", "GlobiGuard returned an unsupported decision; the governed action remains stopped.", authorizationId, queueEntryId);
        }

        if (simulation)
            throw NonExecutable("A dry-run decision is not an execution permit. Reauthorize with dryRun disabled.", authorizationId, queueEntryId);
        if (!result.TryGetProperty("executable", out var executable) || executable.ValueKind != JsonValueKind.True ||
            !result.TryGetProperty("nextAction", out var nextAction) || nextAction.GetString() != "EXECUTE_EXACT_ACTION_ONCE")
            throw NonExecutable("The control plane marked this response as non-executable. Reauthorize before execution.", authorizationId, queueEntryId);

        var approvalState = result.TryGetProperty("approvalState", out var approval) ? approval.GetString() : null;
        if (approvalState is not ("NOT_REQUIRED" or "APPROVED"))
            throw NonExecutable("Resolve review and reauthorize the exact current action before execution.", authorizationId, queueEntryId);

        var current = now ?? DateTimeOffset.UtcNow;
        if (!result.TryGetProperty("expiresAt", out var expiryValue) || expiryValue.ValueKind != JsonValueKind.String ||
            !DateTimeOffset.TryParse(expiryValue.GetString(), out var expiry) || expiry <= current || expiry - current > MaxExecutionAuthorizationTtl)
            throw NonExecutable("Execution authority must have a current, bounded expiry. Reauthorize immediately before execution.", authorizationId, queueEntryId);

        if (result.TryGetProperty("obligations", out var obligations) && obligations.ValueKind == JsonValueKind.Array && obligations.GetArrayLength() > 0)
            throw NonExecutable("Enforce all obligations and reauthorize before execution.", authorizationId, queueEntryId);
        if (result.TryGetProperty("modifications", out var modifications) && modifications.ValueKind == JsonValueKind.Object && modifications.EnumerateObject().Any())
            throw NonExecutable("Apply all modifications and reauthorize the exact resulting action before execution.", authorizationId, queueEntryId);
    }

    private static GlobiguardAuthorityException NonExecutable(string message, string? authorizationId, string? queueEntryId) =>
        new("STEP_UP_REQUIRED", message, authorizationId, queueEntryId);

    private static bool IsDryRun(object body)
    {
        try
        {
            var request = JsonSerializer.SerializeToElement(body);
            return request.ValueKind == JsonValueKind.Object && request.TryGetProperty("dryRun", out var dryRun) && dryRun.ValueKind == JsonValueKind.True;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public Task<JsonElement> RequestApprovalAsync(object request, CancellationToken cancellationToken = default) =>
        _actions.CreateApprovalAsync(request, cancellationToken);

    public Task<JsonElement> GetApprovalStatusAsync(string approvalId, CancellationToken cancellationToken = default) =>
        _actions.GetApprovalAsync(approvalId, cancellationToken);

    public Task<JsonElement> GetEvidencePackageSummaryAsync(string evidencePackageId, CancellationToken cancellationToken = default) =>
        _audit.GetEvidencePackageSummaryAsync(evidencePackageId, cancellationToken);

    public Task<JsonElement> GetIncidentReplayAsync(string lookupKind, string lookupId, CancellationToken cancellationToken = default) =>
        _audit.GetIncidentReplayAsync(lookupKind, lookupId, cancellationToken);

    public async Task<JsonElement> WaitForApprovalAsync(
        string queueEntryId,
        int maxAttempts = 60,
        TimeSpan? interval = null,
        CancellationToken cancellationToken = default)
    {
        if (maxAttempts < 1) throw new ArgumentException("maxAttempts must be at least 1.");
        var delay = interval ?? TimeSpan.FromSeconds(1);
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            var entry = await _queue.GetAsync(queueEntryId, cancellationToken).ConfigureAwait(false);
            var status = entry.TryGetProperty("status", out var statusValue) ? statusValue.GetString() : null;
            if (status is "APPROVED" or "AUTO_APPROVED" or "RESUMED") return entry;
            if (status is "REJECTED" or "EXPIRED" or "FAILED")
                throw new GlobiguardAuthorityException("POLICY_BLOCKED", $"Queued action resolved as {status}; do not perform the downstream business action.", queueEntryId: queueEntryId);
            if (status is "MODIFIED")
                throw new GlobiguardAuthorityException("STEP_UP_REQUIRED", "The reviewer approved a modified action summary. Rebuild the real payload and request a new authorization before executing it.", queueEntryId: queueEntryId);
            if (status is not ("PENDING" or "ESCALATED"))
                throw new GlobiguardAuthorityException("CONTROL_PLANE_UNAVAILABLE", "GlobiGuard returned an unsupported approval state; the downstream business action remains stopped.", queueEntryId: queueEntryId);
            if (attempt < maxAttempts) await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        }
        throw new GlobiguardAuthorityException("QUEUED_FOR_REVIEW", "Queued action is still pending after the configured wait attempts; do not perform the downstream business action yet.", queueEntryId: queueEntryId);
    }
}

public sealed record WebhookResult(bool Ok, string? Error, JsonElement? Envelope);

public static class TrustWebhookVerifier
{
    public static WebhookResult Verify(IReadOnlyDictionary<string, string> headers, byte[] rawBody, string signingSecret, TimeSpan? tolerance = null)
    {
        var deliveryId = Header(headers, "x-globiguard-delivery-id");
        var timestamp = Header(headers, "x-globiguard-timestamp");
        var eventType = Header(headers, "x-globiguard-event-type");
        var signature = Header(headers, "x-globiguard-signature");
        if (deliveryId is null || timestamp is null || eventType is null || signature is null) return new(false, "Missing required webhook headers.", null);
        if (!long.TryParse(timestamp, out var unixSeconds)) return new(false, "Invalid webhook timestamp.", null);
        var age = DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        if (age.Duration() > (tolerance ?? TimeSpan.FromMinutes(5))) return new(false, "Webhook timestamp is outside the replay window.", null);
        var payload = Encoding.UTF8.GetBytes($"globiguard-hmac-sha256-v1.{deliveryId}.{timestamp}.{eventType}.{Encoding.UTF8.GetString(rawBody)}");
        var expected = "v1=" + Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(signingSecret), payload)).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(signature))) return new(false, "Invalid webhook signature.", null);
        return new(true, null, JsonDocument.Parse(rawBody).RootElement.Clone());
    }

    private static string? Header(IReadOnlyDictionary<string, string> headers, string name) =>
        headers.FirstOrDefault(kv => kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
}

public sealed record BootstrapProfile(string Environment, string DeploymentMode, string IssuerMode, string InstallReporting, string? InstallLabel = null);

public static class Bootstrap
{
    public static Dictionary<string, object?> BuildInstallRegistration(BootstrapProfile profile, string packageName, string packageVersion, string integrationKind, string runtimeKind)
    {
        Validate(profile);
        return new()
        {
            ["packageName"] = packageName,
            ["packageVersion"] = packageVersion,
            ["integrationKind"] = integrationKind,
            ["runtimeKind"] = runtimeKind,
            ["environment"] = profile.Environment,
            ["deploymentMode"] = profile.DeploymentMode,
            ["issuerMode"] = profile.IssuerMode,
            ["installReporting"] = profile.InstallReporting,
            ["installLabel"] = profile.InstallLabel,
        };
    }

    private static void Validate(BootstrapProfile profile)
    {
        if (!EnvironmentName.IsValid(profile.Environment)) throw new ArgumentException("Invalid environment.");
        if (profile.DeploymentMode == "hosted" && profile.IssuerMode != "globiguard_issued") throw new ArgumentException("Hosted deployments require globiguard_issued issuer mode.");
        if (profile.DeploymentMode is "self_hosted" or "sovereign")
        {
            if (profile.IssuerMode != "customer_issued") throw new ArgumentException("Self-hosted and sovereign deployments require customer_issued issuer mode.");
            if (profile.InstallReporting is not ("opt_in" or "disabled")) throw new ArgumentException("Self-hosted and sovereign install reporting must be opt_in or disabled.");
        }
    }
}

public sealed record EntitlementVerificationOptions(
    string? ExpectedIssuer = null,
    string? ExpectedOrgId = null,
    string? ExpectedProjectId = null,
    string? ExpectedEnvironment = null,
    string? ExpectedDeploymentMode = null,
    DateTimeOffset? Now = null);

public static class EntitlementManifestVerifier
{
    private const string ManifestType = "globiguard.entitlement.v1";
    private static readonly HashSet<string> Environments = new() { "sandbox", "live" };
    private static readonly HashSet<string> DeploymentModes = new() { "self_hosted", "sovereign" };
    private static readonly HashSet<string> CommercialPlans = new() { "FREE", "STARTER", "GROWTH", "SCALE", "ENTERPRISE" };
    private static readonly HashSet<string> BillingStatuses = new() { "FREE", "PILOT", "ACTIVE", "GRACE", "PAST_DUE", "SUSPENDED", "CANCELED" };
    private static readonly HashSet<string> OverageModes = new() { "NONE", "METERED", "CONTRACT" };

    public static JsonElement Verify(
        string compactJws,
        IReadOnlyDictionary<string, byte[]> publicKeysById,
        Func<byte[], byte[], byte[], bool> verifyEd25519,
        EntitlementVerificationOptions? options = null)
    {
        options ??= new EntitlementVerificationOptions();
        var parts = compactJws.Split('.');
        if (parts.Length != 3) throw new ArgumentException("Entitlement manifest must be compact JWS.");
        using var headerDocument = JsonDocument.Parse(Base64UrlDecode(parts[0]));
        var protectedHeader = headerDocument.RootElement;
        if (RequireString(protectedHeader, "alg") != "EdDSA" || RequireString(protectedHeader, "typ") != ManifestType)
            throw new ArgumentException("Unsupported entitlement manifest protected header.");
        var kid = RequireString(protectedHeader, "kid");
        if (!publicKeysById.TryGetValue(kid, out var publicKey)) throw new ArgumentException("Unknown entitlement signing key.");
        var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        var signature = Base64UrlDecode(parts[2]);
        if (!verifyEd25519(publicKey, signingInput, signature)) throw new CryptographicException("Invalid entitlement manifest signature.");
        using var payloadDocument = JsonDocument.Parse(Base64UrlDecode(parts[1]));
        var payload = payloadDocument.RootElement.Clone();
        ValidatePayload(payload);

        var now = options.Now ?? DateTimeOffset.UtcNow;
        var issuedAt = RequireTimestamp(payload, "issuedAt");
        var notBefore = RequireTimestamp(payload, "notBefore");
        var expiresAt = RequireTimestamp(payload, "expiresAt");
        if (issuedAt > expiresAt || notBefore >= expiresAt) throw new ArgumentException("Entitlement manifest timestamps are inconsistent.");
        if (notBefore > now) throw new ArgumentException("Entitlement manifest is not active yet.");
        if (expiresAt <= now) throw new ArgumentException("Entitlement manifest has expired.");

        var subject = payload.GetProperty("subject");
        Expect(options.ExpectedIssuer, RequireString(payload, "issuer"), "issuer");
        Expect(options.ExpectedOrgId, RequireString(subject, "orgId"), "organization");
        Expect(options.ExpectedProjectId, RequireString(subject, "projectId"), "project");
        Expect(options.ExpectedEnvironment, RequireString(subject, "environment"), "environment");
        Expect(options.ExpectedDeploymentMode, RequireString(subject, "deploymentMode"), "deployment mode");
        return payload;
    }

    private static void ValidatePayload(JsonElement payload)
    {
        if (RequireString(payload, "manifestType") != ManifestType || payload.GetProperty("manifestVersion").GetInt32() != 1)
            throw new ArgumentException("Unsupported entitlement manifest payload.");
        foreach (var field in new[] { "manifestId", "issuer", "issuedAt", "notBefore", "expiresAt" }) RequireString(payload, field);

        var subject = RequireObject(payload, "subject");
        foreach (var field in new[] { "orgId", "workspaceName", "orgSlug", "projectId", "projectSlug" }) RequireString(subject, field);
        if (!Environments.Contains(RequireString(subject, "environment"))) throw new ArgumentException("Entitlement manifest subject environment is invalid.");
        if (!DeploymentModes.Contains(RequireString(subject, "deploymentMode"))) throw new ArgumentException("Entitlement manifest subject deployment mode is invalid.");

        var commercial = RequireObject(payload, "commercial");
        if (!CommercialPlans.Contains(RequireString(commercial, "commercialPlan"))) throw new ArgumentException("Entitlement manifest commercial plan is invalid.");
        if (!BillingStatuses.Contains(RequireString(commercial, "billingStatus"))) throw new ArgumentException("Entitlement manifest billing status is invalid.");
        if (!commercial.TryGetProperty("pilotActive", out var pilotActive) || pilotActive.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new ArgumentException("Entitlement manifest pilotActive must be boolean.");

        var entitlements = RequireObject(payload, "entitlements");
        ValidateNullableCounter(entitlements, "includedQueriesPerMonth");
        ValidateNullableCounter(entitlements, "frameworkSlots");
        if (!OverageModes.Contains(RequireString(entitlements, "overageMode"))) throw new ArgumentException("Entitlement manifest overage mode is invalid.");
    }

    private static JsonElement RequireObject(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Object)
            throw new ArgumentException($"Entitlement manifest field {name} must be an object.");
        return value;
    }

    private static string RequireString(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
            throw new ArgumentException($"Entitlement manifest field {name} must be a non-empty string.");
        return value.GetString()!;
    }

    private static DateTimeOffset RequireTimestamp(JsonElement parent, string name)
    {
        if (!DateTimeOffset.TryParse(RequireString(parent, name), out var value))
            throw new ArgumentException($"Entitlement manifest field {name} must be an ISO timestamp.");
        return value;
    }

    private static void ValidateNullableCounter(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value)) throw new ArgumentException($"Entitlement manifest field {name} is required.");
        if (value.ValueKind == JsonValueKind.Null) return;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var count) || count < 0)
            throw new ArgumentException($"Entitlement manifest field {name} must be null or a non-negative integer.");
    }

    private static void Expect(string? expected, string actual, string label)
    {
        if (expected is not null && !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(actual)))
            throw new ArgumentException($"Entitlement manifest {label} does not match the expected value.");
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        return Convert.FromBase64String(padded);
    }
}

