using System.Text;
using System.Text.Json;
using GlobiGuard;

// PATH VALIDATION TESTS
Transport.ValidatePath("/v1/actions");
ExpectThrows(() => Transport.ValidatePath("https://evil.example/v1"), "should reject absolute URLs");
ExpectThrows(() => Transport.ValidatePath("/v1/../secret"), "should reject parent directory traversal");
ExpectThrows(() => Transport.ValidatePath("/v1/./secret"), "should reject current directory traversal");
ExpectThrows(() => Transport.ValidatePath("/v1%2f../secret"), "should reject encoded parent traversal");
ExpectThrows(() => Transport.ValidatePath("/v1//double"), "should reject double slash");
ExpectThrows(() => Transport.ValidatePath("/v1\\backslash"), "should reject backslash");
ExpectThrows(() => Transport.ValidatePath("/v1?query=1"), "should reject query strings");
ExpectThrows(() => Transport.ValidatePath("/v1#fragment"), "should reject fragments");
ExpectThrows(() => Transport.ValidatePath("/v1%"), "should reject invalid percent encoding");

// CREDENTIAL VALIDATION TESTS
try
{
    var localCred = new Credential("local", "proj_123", null, EnvironmentName.Local);
    Assert(localCred.Kind == "local", "local credential kind");
}
catch (Exception ex)
{
    throw new Exception($"Local credential creation failed: {ex.Message}");
}

try
{
    var secretCred = new Credential("secret", "proj_123", "sk_test", EnvironmentName.Sandbox);
    Assert(secretCred.Kind == "secret", "secret credential kind");
}
catch (Exception ex)
{
    throw new Exception($"Secret credential creation failed: {ex.Message}");
}

try
{
    var pubCred = new Credential("publishable", "proj_123", "pk_test", EnvironmentName.Sandbox);
    Assert(pubCred.Kind == "publishable", "publishable credential kind");
}
catch (Exception ex)
{
    throw new Exception($"Publishable credential creation failed: {ex.Message}");
}

// BOOTSTRAP PROFILE TESTS
var profile = new BootstrapProfile(EnvironmentName.Sandbox, "self_hosted", "customer_issued", "opt_in");
var registration = Bootstrap.BuildInstallRegistration(profile, "GlobiGuard", "0.1.0", "sdk", "dotnet");
Assert((string?)registration["environment"] == EnvironmentName.Sandbox, "bootstrap environment");
Assert((string?)registration["deploymentMode"] == "self_hosted", "bootstrap deployment mode");
Assert((string?)registration["issuerMode"] == "customer_issued", "bootstrap issuer mode");
Assert((string?)registration["installReporting"] == "opt_in", "bootstrap install reporting");
Assert((string?)registration["packageName"] == "GlobiGuard", "bootstrap package name");
Assert((string?)registration["packageVersion"] == "0.1.0", "bootstrap package version");
Assert((string?)registration["integrationKind"] == "sdk", "bootstrap integration kind");
Assert((string?)registration["runtimeKind"] == "dotnet", "bootstrap runtime kind");

// BROWSER AUTHORITY BOUNDARY
var browser = GlobiGuardClient.CreateBrowser(new ClientOptions(
    EnvironmentName.Sandbox,
    new Dictionary<string, string> { ["controlPlane"] = "https://api.globiguard.com" },
    Credential.Publishable("proj_123", "ggpk_test", EnvironmentName.Sandbox)));
ExpectThrows(
    () => browser.Policies.CreateAsync(new { name = "must-not-send" }).GetAwaiter().GetResult(),
    "browser resource writes must fail before transport");

// EXECUTION AUTHORITY BOUNDARY
var authorityNow = DateTimeOffset.UtcNow;
var executableAllow = JsonSerializer.SerializeToElement(new
{
    decision = "ALLOW",
    executable = true,
    nextAction = "EXECUTE_EXACT_ACTION_ONCE",
    approvalState = "NOT_REQUIRED",
    expiresAt = authorityNow.AddMinutes(1),
    obligations = Array.Empty<string>(),
    modifications = new { }
});
GovernedActionsClient.AssertExecutableAuthorization(executableAllow, now: authorityNow);
foreach (var stopped in new[]
{
    JsonSerializer.SerializeToElement(new { decision = "MODIFY" }),
    JsonSerializer.SerializeToElement(new { decision = "QUEUE" }),
    JsonSerializer.SerializeToElement(new { decision = "BLOCK" }),
    JsonSerializer.SerializeToElement(new { decision = "UNKNOWN" }),
    JsonSerializer.SerializeToElement(new { decision = "ALLOW", executable = false, nextAction = "EXECUTE_EXACT_ACTION_ONCE", approvalState = "NOT_REQUIRED", expiresAt = authorityNow.AddMinutes(1) }),
    JsonSerializer.SerializeToElement(new { decision = "ALLOW", executable = true, nextAction = "REAUTHORIZE_EXACT_ACTION", approvalState = "NOT_REQUIRED", expiresAt = authorityNow.AddMinutes(1) }),
    JsonSerializer.SerializeToElement(new { decision = "ALLOW", executable = true, nextAction = "EXECUTE_EXACT_ACTION_ONCE", approvalState = "PENDING", expiresAt = authorityNow.AddMinutes(1) }),
    JsonSerializer.SerializeToElement(new { decision = "ALLOW", executable = true, nextAction = "EXECUTE_EXACT_ACTION_ONCE", approvalState = "NOT_REQUIRED", expiresAt = authorityNow.AddMinutes(10) }),
    JsonSerializer.SerializeToElement(new { decision = "ALLOW", executable = true, nextAction = "EXECUTE_EXACT_ACTION_ONCE", approvalState = "NOT_REQUIRED", expiresAt = authorityNow.AddMinutes(1), obligations = new[] { "redact" } }),
    JsonSerializer.SerializeToElement(new { decision = "ALLOW", executable = true, nextAction = "EXECUTE_EXACT_ACTION_ONCE", approvalState = "NOT_REQUIRED", expiresAt = authorityNow.AddMinutes(1), modifications = new { recipient = "safe" } })
})
{
    ExpectThrows(() => GovernedActionsClient.AssertExecutableAuthorization(stopped, now: authorityNow), "unresolved authority must fail closed");
}
ExpectThrows(() => GovernedActionsClient.AssertExecutableAuthorization(executableAllow, simulation: true, now: authorityNow), "dry-run ALLOW must fail closed");

// CURRENT ENTITLEMENT MANIFEST CONTRACT
var entitlementHeader = JsonSerializer.Serialize(new
{
    alg = "EdDSA",
    kid = "kid_test",
    typ = "globiguard.entitlement.v1"
});
var entitlementPayload = JsonSerializer.Serialize(new
{
    manifestType = "globiguard.entitlement.v1",
    manifestVersion = 1,
    manifestId = "manifest_123",
    issuer = "https://api.globiguard.com",
    issuedAt = "2026-05-29T10:00:00Z",
    notBefore = "2026-05-29T10:00:00Z",
    expiresAt = "2026-05-30T10:00:00Z",
    subject = new
    {
        orgId = "org_123",
        workspaceName = "Acme",
        orgSlug = "acme",
        projectId = "proj_123",
        projectSlug = "main",
        environment = "sandbox",
        deploymentMode = "self_hosted"
    },
    commercial = new
    {
        commercialPlan = "GROWTH",
        billingStatus = "ACTIVE",
        pilotActive = false
    },
    entitlements = new
    {
        includedQueriesPerMonth = 10_000,
        frameworkSlots = 3,
        overageMode = "METERED"
    }
});
var entitlementToken = $"{Base64Url(entitlementHeader)}.{Base64Url(entitlementPayload)}.{Base64Url("signature")}";
var verifiedEntitlement = EntitlementManifestVerifier.Verify(
    entitlementToken,
    new Dictionary<string, byte[]> { ["kid_test"] = Encoding.UTF8.GetBytes("public-key") },
    (_, signingInput, signatureBytes) =>
        Encoding.ASCII.GetString(signingInput).StartsWith(Base64Url(entitlementHeader) + ".", StringComparison.Ordinal)
        && Encoding.UTF8.GetString(signatureBytes) == "signature",
    new EntitlementVerificationOptions(
        ExpectedIssuer: "https://api.globiguard.com",
        ExpectedOrgId: "org_123",
        ExpectedProjectId: "proj_123",
        ExpectedEnvironment: "sandbox",
        ExpectedDeploymentMode: "self_hosted",
        Now: DateTimeOffset.Parse("2026-05-29T10:30:00Z")));
Assert(
    verifiedEntitlement.GetProperty("commercial").GetProperty("commercialPlan").GetString() == "GROWTH",
    "current entitlement manifest verification");
ExpectThrows(
    () => EntitlementManifestVerifier.Verify(
        entitlementToken,
        new Dictionary<string, byte[]> { ["kid_test"] = Encoding.UTF8.GetBytes("public-key") },
        (_, _, _) => true,
        new EntitlementVerificationOptions(ExpectedOrgId: "org_other", Now: DateTimeOffset.Parse("2026-05-29T10:30:00Z"))),
    "entitlement subject mismatch must fail closed");

// WEBHOOK VERIFICATION TESTS
var body = Encoding.UTF8.GetBytes("{\"type\":\"globiguard.test\"}");
var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
var delivery = "del_test";
var secret = "whsec_test";
var payload = Encoding.UTF8.GetBytes($"globiguard-hmac-sha256-v1.{delivery}.{timestamp}.globiguard.test.{Encoding.UTF8.GetString(body)}");
var signature = "v1=" + Convert.ToHexString(System.Security.Cryptography.HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), payload)).ToLowerInvariant();

var result = TrustWebhookVerifier.Verify(new Dictionary<string, string>
{
    ["x-globiguard-delivery-id"] = delivery,
    ["x-globiguard-timestamp"] = timestamp,
    ["x-globiguard-event-type"] = "globiguard.test",
    ["x-globiguard-signature"] = signature
}, body, secret);
Assert(result.Ok, "webhook verification with valid signature");

// WEBHOOK INVALID SIGNATURE TEST
var invalidSignature = "v1=" + Convert.ToHexString(System.Security.Cryptography.HMACSHA256.HashData(Encoding.UTF8.GetBytes("wrong_secret"), payload)).ToLowerInvariant();
var invalidResult = TrustWebhookVerifier.Verify(new Dictionary<string, string>
{
    ["x-globiguard-delivery-id"] = delivery,
    ["x-globiguard-timestamp"] = timestamp,
    ["x-globiguard-event-type"] = "globiguard.test",
    ["x-globiguard-signature"] = invalidSignature
}, body, secret);
Assert(!invalidResult.Ok, "webhook verification should reject invalid signature");

// WEBHOOK REPLAY WINDOW TEST (old timestamp)
var oldTimestamp = (DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 400).ToString();
var oldPayload = Encoding.UTF8.GetBytes($"globiguard-hmac-sha256-v1.{delivery}.{oldTimestamp}.globiguard.test.{Encoding.UTF8.GetString(body)}");
var oldSignature = "v1=" + Convert.ToHexString(System.Security.Cryptography.HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), oldPayload)).ToLowerInvariant();
var replayResult = TrustWebhookVerifier.Verify(new Dictionary<string, string>
{
    ["x-globiguard-delivery-id"] = delivery,
    ["x-globiguard-timestamp"] = oldTimestamp,
    ["x-globiguard-event-type"] = "globiguard.test",
    ["x-globiguard-signature"] = oldSignature
}, body, secret);
Assert(!replayResult.Ok, "webhook verification should reject old timestamps");

// MISSING HEADER TESTS
var missingDeliveryResult = TrustWebhookVerifier.Verify(new Dictionary<string, string>
{
    ["x-globiguard-timestamp"] = timestamp,
    ["x-globiguard-event-type"] = "globiguard.test",
    ["x-globiguard-signature"] = signature
}, body, secret);
Assert(!missingDeliveryResult.Ok, "webhook verification should require delivery ID header");

var missingSignatureResult = TrustWebhookVerifier.Verify(new Dictionary<string, string>
{
    ["x-globiguard-delivery-id"] = delivery,
    ["x-globiguard-timestamp"] = timestamp,
    ["x-globiguard-event-type"] = "globiguard.test"
}, body, secret);
Assert(!missingSignatureResult.Ok, "webhook verification should require signature header");

Console.WriteLine("GlobiGuard .NET SDK comprehensive tests passed.");

static void Assert(bool condition, string name)
{
    if (!condition) throw new Exception($"Assertion failed: {name}");
}

static void ExpectThrows(Action action, string name)
{
    try
    {
        action();
    }
    catch
    {
        return;
    }
    throw new Exception($"Expected exception: {name}");
}

static string Base64Url(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
    .TrimEnd('=')
    .Replace('+', '-')
    .Replace('/', '_');

