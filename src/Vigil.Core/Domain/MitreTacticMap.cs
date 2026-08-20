namespace Vigil.Core.Domain;

/// <summary>
/// Static MITRE ATT&amp;CK technique → tactic lookup used by the stats
/// heatmap. Covers the techniques Vigil's email/cloud pipelines actually
/// emit — extend as needed. IDs not listed here (and whose parent technique
/// is not listed either) report tactic <see cref="UnknownTactic"/>.
/// </summary>
public static class MitreTacticMap
{
    public const string UnknownTactic = "Unknown";

    /// <summary>
    /// Canonical ATT&amp;CK kill-chain order; the heatmap frontend renders
    /// columns in this order. <see cref="UnknownTactic"/> stays last.
    /// </summary>
    public static readonly IReadOnlyList<string> TacticOrder =
    [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
        UnknownTactic
    ];

    private static readonly IReadOnlyDictionary<string, string> ByTechnique =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // Initial Access — phishing & co.
            ["T1566"] = "Initial Access", // Phishing
            ["T1566.001"] = "Initial Access", // Spearphishing Attachment
            ["T1566.002"] = "Initial Access", // Spearphishing Link
            ["T1566.003"] = "Initial Access", // Spearphishing via Service
            ["T1078"] = "Initial Access", // Valid Accounts (also Persistence; primary here)
            ["T1190"] = "Initial Access", // Exploit Public-Facing Application
            ["T1189"] = "Initial Access", // Drive-by Compromise
            ["T1195"] = "Initial Access", // Supply Chain Compromise

            // Execution
            ["T1059"] = "Execution", // Command and Scripting Interpreter
            ["T1204"] = "Execution", // User Execution
            ["T1204.002"] = "Execution", // Malicious File

            // Persistence
            ["T1078.004"] = "Persistence", // Valid Accounts: Cloud Accounts
            ["T1098"] = "Persistence", // Account Manipulation
            ["T1136"] = "Persistence", // Create Account
            ["T1053"] = "Persistence", // Scheduled Task/Job

            // Privilege Escalation
            ["T1068"] = "Privilege Escalation", // Exploitation for Privilege Escalation
            ["T1548"] = "Privilege Escalation", // Abuse Elevation Control Mechanism

            // Defense Evasion
            ["T1562"] = "Defense Evasion", // Impair Defenses
            ["T1562.008"] = "Defense Evasion", // Impair Defenses: Disable or Modify Cloud Logs
            ["T1027"] = "Defense Evasion", // Obfuscated Files or Information
            ["T1070"] = "Defense Evasion", // Indicator Removal
            ["T1055"] = "Defense Evasion", // Process Injection

            // Credential Access
            ["T1110"] = "Credential Access", // Brute Force
            ["T1110.003"] = "Credential Access", // Password Spraying
            ["T1003"] = "Credential Access", // OS Credential Dumping
            ["T1552"] = "Credential Access", // Unsecured Credentials
            ["T1552.005"] = "Credential Access", // Cloud Instance Metadata API
            ["T1557"] = "Credential Access", // Adversary-in-the-Middle

            // Discovery
            ["T1087"] = "Discovery", // Account Discovery
            ["T1083"] = "Discovery", // File and Directory Discovery
            ["T1018"] = "Discovery", // Remote System Discovery
            ["T1046"] = "Discovery", // Network Service Discovery
            ["T1069"] = "Discovery", // Permission Groups Discovery

            // Lateral Movement
            ["T1021"] = "Lateral Movement", // Remote Services
            ["T1080"] = "Lateral Movement", // Taint Shared Content

            // Command and Control
            ["T1105"] = "Command and Control", // Ingress Tool Transfer
            ["T1071"] = "Command and Control", // Application Layer Protocol
            ["T1102"] = "Command and Control", // Web Service
            ["T1573"] = "Command and Control", // Encrypted Channel

            // Exfiltration
            ["T1041"] = "Exfiltration", // Exfiltration Over C2 Channel
            ["T1048"] = "Exfiltration", // Exfiltration Over Alternative Protocol
            ["T1567"] = "Exfiltration", // Exfiltration Over Web Service
            ["T1567.002"] = "Exfiltration", // Exfiltration to Cloud Storage
            ["T1537"] = "Exfiltration", // Transfer Data to Cloud Account

            // Impact
            ["T1526"] = "Impact", // Cloud Service Discovery / cloud-impact scenarios
            ["T1485"] = "Impact", // Data Destruction
            ["T1486"] = "Impact", // Data Encrypted for Impact
            ["T1490"] = "Impact", // Inhibit System Recovery
            ["T1496"] = "Impact", // Resource Hijacking
            ["T1498"] = "Impact", // Network Denial of Service
        };

    /// <summary>
    /// Resolves a technique ID to its tactic. Falls back to the parent
    /// technique for unmapped sub-techniques (e.g. "T1059.001" → "T1059"),
    /// then to <see cref="UnknownTactic"/>.
    /// </summary>
    public static string GetTactic(string techniqueId)
    {
        if (ByTechnique.TryGetValue(techniqueId, out var tactic))
        {
            return tactic;
        }

        var dot = techniqueId.IndexOf('.');
        if (dot > 0 && ByTechnique.TryGetValue(techniqueId[..dot], out tactic))
        {
            return tactic;
        }

        return UnknownTactic;
    }
}
