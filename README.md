# SandboxTest
Using Sentinel to Detect and Investigate Suspicious Authentication Behavior

**Objective:** Build a small Microsoft Sentinel environment and test whether Windows authentication telemetry could be collected and investigated.

**Environment:** Azure Resource Group, virtual network, Windows VM `CORP-EAST-US-1`, Log Analytics Workspace `LAW-soc-lab`, Data Collection Rule `DCR-Windows`, and Microsoft Sentinel.

**Test scenario:** Remove the NSG firewall and the endpoint firewall. Either wait for login attempts or generate controlled failed authentication attempts against the Windows VM so there is known suspicious activity to investigate.

**Telemetry collection:** Configure the VM and Data Collection Rule to forward Windows Security events into Log Analytics/Sentinel.

**Investigation:** Query `SecurityEvent` for Event ID 4625, review the affected account, timestamp, host, activity, and source IP information, then summarize failed attempts by target account to identify repeated authentication failures.

SecurityEvent
| where TimeGenerated > ago(1d)
|where EventID == "4625"
| project TimeGenerated, EventID, Account, Computer, IpAddress, Activity
| order by TimeGenerated desc

**Finding:** Confirm Sentinel received the authentication events generated during the test and that the failed logons could be identified and analyzed through KQL.

// Password Spray Detection via Windows Security Events
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625
// Filter out null or system IP addresses
| where isnotempty(IpAddress) and IpAddress != "-" and IpAddress != "127.0.0.1"
| summarize 
    TotalFailures = count(5), 
    UniqueTargetAccounts = dcount(TargetAccount), 
    AttemptedAccounts = make_set(TargetAccount, 20) 
    by IpAddress, bin(TimeGenerated, 1h)
// Trigger if a single IP hits more than 10 distinct usernames
| where UniqueTargetAccounts > 10
| sort by UniqueTargetAccounts desc

**Mitigation** 
Lock Attempts from Custom IP Address, Ban Passwords, etc in Sentinel > Security > Authentication Methods >  Manage > Password Protection

**Conclusion**
Remove the Allow Any rule from the NSG, replace with original RDP rule.
Turn the Endpoint Firewall back on.

