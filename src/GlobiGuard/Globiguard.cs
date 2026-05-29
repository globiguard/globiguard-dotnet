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

public sealed class GlobiGuardClient
{
    private readonly Transport _transport;
    public ResourceClient Actions { get; }
    public ResourceClient Audit { get; }
    public ResourceClient Installs { get; }
    public ResourceClient Orgs { get; }
    public ResourceClient Policies { get; }
    public ResourceClient Queue { get; }
    public ResourceClient Workflows { get; }
    public GovernedActionsClient GovernedActions { get; }

    private GlobiGuardClient(Transport transport)
    {
        _transport = transport;
        Actions = new ResourceClient(transport, "/v1/actions");
        Audit = new ResourceClient(transport, "/v1/audit");
        Installs = new ResourceClient(transport, "/v1/installs");
        Orgs = new ResourceClient(transport, "/v1/orgs");
        Policies = new ResourceClient(transport, "/v1/policies");
        Queue = new ResourceClient(transport, "/v1/queue");
        Workflows = new ResourceClient(transport, "/v1/workflows");
        GovernedActions = new GovernedActionsClient(transport);
    }

    public static GlobiGuardClient CreateServer(ClientOptions options)
    {
        if (options.Credential.Kind == "publishable") throw new ArgumentException("Server clients require secret or local credentials.");
        return new GlobiGuardClient(new Transport(options));
    }

    public static GlobiGuardClient CreateBrowser(ClientOptions options)
    {
        if (options.Credential.Kind == "secret") throw new ArgumentException("Browser clients cannot use secret credentials.");
        return new GlobiGuardClient(new Transport(options));
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

    public async Task<JsonElement> RequestAsync(HttpMethod method, string path, object? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
    {
        ValidatePath(path);
        var uri = new Uri(new Uri(_options.Services["controlPlane"].TrimEnd('/') + "/"), path.TrimStart('/'));
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
        if (path.StartsWith("//") || path.Contains('\\') || path.Contains('?') || path.Contains('#')) throw new ArgumentException("Unsafe request path.");
        if (Uri.TryCreate(path, UriKind.Absolute, out _)) throw new ArgumentException("Absolute request paths are not allowed.");
        if (path.Split('/').Any(segment => segment is "." or "..")) throw new ArgumentException("Dot segments are not allowed.");
        if (Regex.IsMatch(path, "%(?![0-9A-Fa-f]{2})")) throw new ArgumentException("Invalid percent encoding.");
    }
}

public sealed class ResourceClient
{
    private readonly Transport _transport;
    private readonly string _basePath;
    public ResourceClient(Transport transport, string basePath) { _transport = transport; _basePath = basePath; }
    public Task<JsonElement> ListAsync(CancellationToken cancellationToken = default) => _transport.RequestAsync(HttpMethod.Get, _basePath, cancellationToken: cancellationToken);
    public Task<JsonElement> GetAsync(string id, CancellationToken cancellationToken = default) => _transport.RequestAsync(HttpMethod.Get, $"{_basePath}/{Uri.EscapeDataString(id)}", cancellationToken: cancellationToken);
    public Task<JsonElement> CreateAsync(object body, CancellationToken cancellationToken = default) => _transport.RequestAsync(HttpMethod.Post, _basePath, body, cancellationToken: cancellationToken);
    public Task<JsonElement> PostAsync(string suffix, object body, CancellationToken cancellationToken = default) => _transport.RequestAsync(HttpMethod.Post, $"{_basePath}/{suffix.TrimStart('/')}", body, cancellationToken: cancellationToken);
}

public sealed class GovernedActionsClient
{
    private readonly Transport _transport;
    public GovernedActionsClient(Transport transport) => _transport = transport;

    public async Task<JsonElement> AuthorizeActionOrThrowAsync(object body, string? idempotencyKey = null, string? correlationId = null, CancellationToken cancellationToken = default)
    {
        var headers = new Dictionary<string, string>();
        if (idempotencyKey is not null) headers["Idempotency-Key"] = idempotencyKey;
        if (correlationId is not null) headers["x-correlation-id"] = correlationId;
        var result = await _transport.RequestAsync(HttpMethod.Post, "/v1/actions/authorize", body, headers, cancellationToken).ConfigureAwait(false);
        if (result.TryGetProperty("decision", out var decision) && decision.GetString() is "BLOCK") throw new InvalidOperationException("GlobiGuard blocked the governed action.");
        return result;
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
            ["environment"] = profile.Environment,
            ["deploymentMode"] = profile.DeploymentMode,
            ["issuerMode"] = profile.IssuerMode,
            ["installReporting"] = profile.InstallReporting,
            ["installLabel"] = profile.InstallLabel,
            ["package"] = new Dictionary<string, object?> { ["name"] = packageName, ["version"] = packageVersion },
            ["integration"] = new Dictionary<string, object?> { ["kind"] = integrationKind, ["runtime"] = runtimeKind }
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

public static class EntitlementManifestVerifier
{
    public static JsonElement Verify(string compactJws, IReadOnlyDictionary<string, byte[]> publicKeysById, Func<byte[], byte[], byte[], bool> verifyEd25519)
    {
        var parts = compactJws.Split('.');
        if (parts.Length != 3) throw new ArgumentException("Entitlement manifest must be compact JWS.");
        var protectedHeader = JsonDocument.Parse(Base64UrlDecode(parts[0])).RootElement;
        if (protectedHeader.GetProperty("alg").GetString() != "EdDSA") throw new ArgumentException("Entitlement manifest must use EdDSA.");
        var kid = protectedHeader.GetProperty("kid").GetString() ?? throw new ArgumentException("Missing key id.");
        if (!publicKeysById.TryGetValue(kid, out var publicKey)) throw new ArgumentException("Unknown entitlement signing key.");
        var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        var signature = Base64UrlDecode(parts[2]);
        if (!verifyEd25519(publicKey, signingInput, signature)) throw new CryptographicException("Invalid entitlement manifest signature.");
        var payload = JsonDocument.Parse(Base64UrlDecode(parts[1])).RootElement.Clone();
        if (payload.GetProperty("schema").GetString() != "globiguard.entitlement_manifest.v1") throw new ArgumentException("Unsupported entitlement manifest schema.");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (payload.TryGetProperty("nbf", out var nbf) && nbf.GetInt64() > now) throw new ArgumentException("Entitlement manifest is not active yet.");
        if (payload.TryGetProperty("exp", out var exp) && exp.GetInt64() <= now) throw new ArgumentException("Entitlement manifest is expired.");
        return payload;
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        return Convert.FromBase64String(padded);
    }
}

