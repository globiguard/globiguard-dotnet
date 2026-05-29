using System.Text;
using GlobiGuard;

Transport.ValidatePath("/v1/actions");
ExpectThrows(() => Transport.ValidatePath("https://evil.example/v1"));
ExpectThrows(() => Transport.ValidatePath("/v1/../secret"));

var profile = new BootstrapProfile(EnvironmentName.Sandbox, "self_hosted", "customer_issued", "opt_in");
var registration = Bootstrap.BuildInstallRegistration(profile, "GlobiGuard", "0.1.0", "sdk", "dotnet");
Assert((string?)registration["environment"] == EnvironmentName.Sandbox, "bootstrap environment");

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
Assert(result.Ok, "webhook verification");

Console.WriteLine("GlobiGuard .NET SDK smoke tests passed.");

static void Assert(bool condition, string name)
{
    if (!condition) throw new Exception($"Assertion failed: {name}");
}

static void ExpectThrows(Action action)
{
    try
    {
        action();
    }
    catch
    {
        return;
    }
    throw new Exception("Expected exception.");
}

