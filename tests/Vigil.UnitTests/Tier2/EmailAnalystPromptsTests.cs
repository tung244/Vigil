using Vigil.Core.Tier2;

namespace Vigil.UnitTests.Tier2;

public class EmailAnalystPromptsTests
{
    [Fact]
    public void System_prompt_declares_the_full_json_contract()
    {
        foreach (var token in new[]
                 {
                     "\"status\"", "phishing", "suspicious", "safe",
                     "\"confidence\"", "\"iocs\"", "\"type\"", "\"value\"",
                     "\"phishing_indicators\"", "\"summary\""
                 })
        {
            Assert.Contains(token, EmailAnalystPrompts.SystemPrompt);
        }
    }

    [Fact]
    public void User_prompt_embeds_payload_rules_and_tool_output()
    {
        var prompt = EmailAnalystPrompts.BuildUserPrompt(
            "Subject: verify your account", ["urgent_action_required"], """{"urls":["https://x.example"]}""");

        Assert.Contains("Subject: verify your account", prompt);
        Assert.Contains("urgent_action_required", prompt);
        Assert.Contains("""{"urls":["https://x.example"]}""", prompt);
    }

    [Fact]
    public void User_prompt_truncates_oversized_payloads()
    {
        var payload = new string('a', 5000);

        var prompt = EmailAnalystPrompts.BuildUserPrompt(payload, [], "{}");

        Assert.Contains(new string('a', 4000), prompt);
        Assert.DoesNotContain(new string('a', 4001), prompt);
        Assert.Contains("truncated", prompt);
    }

    [Fact]
    public void User_prompt_handles_empty_rule_list()
    {
        var prompt = EmailAnalystPrompts.BuildUserPrompt("payload", [], "{}");

        Assert.Contains("matched rules: none", prompt);
    }
}
