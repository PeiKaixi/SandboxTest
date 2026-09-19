# SandboxTest
Using Sentinel to Detect and Investigate Suspicious Authentication Behavior

**Objective:** Build a small Microsoft Sentinel environment and test whether Windows authentication telemetry could be collected and investigated.

**Environment:** Azure Resource Group, virtual network, Windows VM `CORP-EAST-US-1`, Log Analytics Workspace `LAW-soc-lab`, Data Collection Rule `DCR-Windows`, and Microsoft Sentinel.

**Test scenario:** Generate controlled failed authentication attempts against the Windows VM so there is known suspicious activity to investigate.

**Telemetry collection:** Configure the VM and Data Collection Rule to forward Windows Security events into Log Analytics/Sentinel.

**Investigation:** Query `SecurityEvent` for Event ID 4625, review the affected account, timestamp, host, activity, and source IP information, then summarize failed attempts by target account to identify repeated authentication failures.

**Finding:** Confirm Sentinel received the authentication events generated during the test and that the failed logons could be identified and analyzed through KQL.
