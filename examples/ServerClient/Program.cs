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
    ["target"] = new Dictionary<string, object?> { ["id"] = "order_456" },
    ["reason"] = "Customer support refund approval"
});

Console.WriteLine(decision);

