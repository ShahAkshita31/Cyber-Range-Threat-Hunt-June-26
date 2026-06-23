
# Threat Hunt Report: Second Vector

**Analyst:** Akshita Shah

**Date Completed:** 2026-06-23  

**Environment Investigated:** law-cyber-range 

**Timeframe:** 2026-06-11 03:00 UTC - 2026-06-11 13:00 UTC

**Status:** Inherited from night shift

---

## Executive Summary

### Executive Summary

A **low-severity Entra ID Protection alert** involving **[m.smith@lognpacific.org](mailto:m.smith@lognpacific.org)** was investigated and confirmed to be a successful Microsoft 365 account compromise. The attacker gained access through a valid authenticated session after Conditional Access controls were not applied, allowing them to operate within the environment without triggering additional authentication challenges.

**Key Findings:**

* Performed reconnaissance using Microsoft Graph API to enumerate tenant resources and user access.
* Reviewed payment-related communications and identified **[j.reynolds@lognpacific.org](mailto:j.reynolds@lognpacific.org)** as the fraud target.
* Established persistence through malicious inbox rules and a Power Automate workflow.
* Accessed Microsoft 365 services including Exchange Online, Teams, SharePoint, and OneDrive.
* Accessed and downloaded sensitive files containing financial and credential-related information.
* Used automated forwarding and mailbox manipulation to conceal activity and support a Business Email Compromise (BEC) campaign.

Evidence confirmed that the incident was a Business Email Compromise (BEC) involving account takeover, internal reconnaissance, persistence through malicious mailbox rules and Power Automate workflows, and unauthorized access to sensitive business data.

---

## Hunt Scope

- **Lab Environment:** Cyber Range
- **Platform:** Defender XDR
- **workspace:** law-cyber-range
- **Data Sources:**
  - SigninLogs
  - MicrosoftGraphActivityLogs
  - OfficeActivity
  - EmailEvents
- **Timeframe:** 2026-06-11 03:00 UTC - 2026-06-11 13:00 UTC
- **Objective:** Investigate the suspicious sign-in associated with **[m.smith@lognpacific.org](mailto:m.smith@lognpacific.org)**, determine the scope and impact of the compromise, identify attacker activity and persistence mechanisms, and assess any evidence of fraud or data exfiltration.

---

## Timeline of Key Events

## Timeline

| **Time (UTC)** | **Flag** | **Action Observed** | **Key Evidence** |
|----------------|----------|---------------------|------------------|
| *2025-10-09T12:22:27.6588913Z* | Flag 1 | The comprmised Principal | `m.smith@lognpacific.org` |
| *2025-10-09T12:34:59.1260624Z* | Flag 2 | The flagged source | `103.69.224.136` |
| *2025-10-09T12:50:39.955931Z* | Flag 3 | The Client OS | `Linux` |
| *2025-10-09T12:51:44.3425653Z* | Flag 4 | The Stored Detection Type | `anonymizedIPAddress` |
| *2025-10-09T12:51:18.3848072Z* | Flag 5 | Audit the verdict | `dismissed` |
| *2025-10-09T12:51:32.5900538Z* | Flag 6 | Live Exposure| `Enabled` |
| *2025-10-09T12:50:58.3174145Z* | Flag 7 | How the session beat MFA | `singleFactorAuthentication` |
| *2025-10-09T12:51:57.6399526Z* | Flag 8 | The control surface that let them in | `One Outlook Web` |
| *2025-10-09T12:52:14.3135459Z* | Flag 9 | Failed Attempts before entry | `2`|
| *2025-10-09T12:55:05.7658713Z* | Flag 10 | Blast Radius of one token | `7` |
| *2025-10-09T12:58:17.4364257Z* | Flag 11 | One continuous session | `005d431a-380b-1f5e-e554-16d5010dc28e` |
| *2025-10-09T13:00:40.045127Z* | Flag 12 | MFA-Posture profiling | `userRegistrationDetails` |
| *2025-10-09T13:01:28.7700443Z* | Flag 13 | Group Enumeration | `/v1.0/me/memberOf` |
|  | Flag 14 | The Fraudulent Request | `Updated Banking Details - Pacific IT Monthly` |
| *2025-10-09T13:02:41.5698148Z* | Flag 15 | The thread they mined | `Q1 Vendor Payment Schedule - Review Required` |
| *2025-10-09T12:22:27.6588913Z* | Flag 16 | The Fraud Target | `j.reynolds@lognpacific.org ` |
| *2025-10-09T12:34:59.1260624Z* | Flag 17 | Second Channel Reinforcement | `Microsoft Teams` |
| *2025-10-09T12:50:39.955931Z* | Flag 18 | The Concealment Rule | `Invoice Processing` |
| *2025-10-09T12:51:44.3425653Z* | Flag 19 | Whaere the Hidden Mail goes | `Hide replies without alerting the user` |
| *2025-10-09T12:51:18.3848072Z* | Flag 20 | The Exfiltration Rule | `merovingian1337@proton.me` |
| *2025-10-09T12:51:32.5900538Z* | Flag 21 | Who Both Rules Target| `Hide and monitor replies to the fraudulent payment request` |
| *2025-10-09T12:50:58.3174145Z* | Flag 22 | The Exfil Operation | FileDownloaded — distinguished from normal FileAccessed activity because it created a local copy of the file outside Microsoft 365, rather than simply viewing it within the service. |
| *2025-10-09T12:51:57.6399526Z* | Flag 23 | Volume Taken | 3 — the small number of downloads indicates focused exfiltration of specific documents, not opportunistic mass data theft.  |
| *2025-10-09T12:52:14.3135459Z* | Flag 24 | The Credential Document | `VPN-Access-Credentials.txt`|
| *2025-10-09T12:55:05.7658713Z* | Flag 25 | The Vault Pointer | `yomark.pdf` |
| *2025-10-09T12:58:17.4364257Z* | Flag 26 | Disapprove the Innocent Explaination | `0` |
| *2025-10-09T13:00:40.045127Z* | Flag 27 | Catch the Plant | `Microsoft Flow Portal` |
| *2025-10-09T13:01:28.7700443Z* | Flag 28 | The cause behind the forward | `MicrosoftGraphActivityLogs` |
|  | Flag 29 | Prove it with the sequence | `Graph Call` |
| *2025-10-09T13:02:41.5698148Z* | Flag 30 | The Automation source IP | `20.150.129.194 ` |
| *2025-10-09T12:22:27.6588913Z* | Flag 31 | The Automation Identity | `7ab7862c-4c57-491e-8a45-d52a7e023983 ` |
| *2025-10-09T12:34:59.1260624Z* | Flag 32 | Name the abused service | `Power Automate` |
| *2025-10-09T12:50:39.955931Z* | Flag 33 | One Actor, Every Source | `7` |
| *2025-10-09T12:51:44.3425653Z* | Flag 34 | Containment Ordering | `Revoke user sessions` |
| *2025-10-09T12:51:18.3848072Z* | Flag 35 | Where the flow is removed | `Power Platform Admin Center` |
| *2025-10-09T12:51:32.5900538Z* | Flag 36 | The Control that never fired | CA was not applied, so the legacy client bypassed policy.  |
| *2025-10-09T12:50:58.3174145Z* | Flag 37 | Why Revoke before reset | Active refresh tokens survive a password reset; revoke user sessions first. |

---

## Starting Point – Identifying the Initial System

**Objective:**
Determine where to begin hunting based on the provided indicators that remote support tools and helpdesk-related files were recently accessed and executed from the Downloads folder during early October.

- **Host of Interest:** `gab-intern-vm`  
- **Why:** This device showed the clearest pattern of suspicious support-tool executions from the Downloads folder on October 9th, 2025, at 12:22 PM, matching the initial compromise pattern.
- **KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between(datetime(2025-10-01)..datetime(2025-10-15))
| where FolderPath has @"\Downloads\" or ProcessCommandLine has @"\Downloads\"
| where ProcessCommandLine matches regex @"(?i)(support|help|desk|tool)"
    or FileName matches regex @"(?i)(support|help|desk|tool)"
    or FolderPath matches regex @"(?i)(support|help|desk|tool)"
| project TimeGenerated, DeviceName, FileName, FolderPath, 
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="2041" height="474" alt="Screenshot 2025-11-14 194024" src="https://github.com/user-attachments/assets/146c8791-0df3-4c38-bf4a-004b35ed6439" />

---

## Flag Analysis

### Flag 1 – Initial Execution Point
- **Objective:** Identify the first CLI parameter used during initial execution.
- **Hypothesis:** Malicious actors often launch scripts with non-default execution policies.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FolderPath has @"\Downloads\" or ProcessCommandLine has @"\Downloads\"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by TimeGenerated asc
| take 20
```
<img width="1933" height="498" alt="flag1" src="https://github.com/user-attachments/assets/b02fff14-dd90-4594-aafb-4fd5c8cbed9a" />

- **Evidence Collected:** `-ExecutionPolicy` in CLI
- **Final Finding:** The attack began with PowerShell launched from Downloads using the `-ExecutionPolicy` argument.

### Flag 2 – Defense Disabling
- **Objective:** Identify files related to simulated security posture changes.
- **Hypothesis:** Creation of tamper artifacts indicates intent to bypass defenses.
- **KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between (datetime(2025-10-09T12:20:00Z)..datetime(2025-10-09T13:00:00Z))
| where InitiatingProcessFileName in ("powershell.exe", "explorer.exe", "notepad.exe") and FileName contains "tamper"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1993" height="553" alt="flag2" src="https://github.com/user-attachments/assets/eaaf8938-a8a6-49ae-b7e2-4b7abba181b5" />

- **Evidence Collected:** `DefenderTamperArtifact.lnk`
- **Final Finding:** Malicious actor staged a tamper artifact to simulate security changes.

### Flag 3 – Quick Data Probe
- **Objective:** Detect opportunistic access to sensitive data sources.
- **Hypothesis:** Short-lived clipboard probes are common pre-collection steps.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between (datetime(2025-10-09T12:20:00Z)..datetime(2025-10-09T13:00:00Z))
| where ProcessCommandLine has "Get-Clipboard" or ProcessCommandLine has "clip.exe" or ProcessCommandLine has "Get-Clip"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1500" height="532" alt="flag3" src="https://github.com/user-attachments/assets/0a4b365a-fd89-4c95-aa1b-e7eabf20640e" />

- **Evidence Collected:** `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`
- **Final Finding:** Early-stage reconnaissance probed clipboard content.

### Flag 4 – Host Context Recon
- **Objective:** Identify basic host and user context collection.
- **Hypothesis:** Actors gather environment and account information before further actions.
- **KQL Query Used:**
```
let startTime = datetime(2025-10-01);
let endTime   = datetime(2025-10-15);
let recon_terms = dynamic(["qwinsta","quser","query user","query"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (startTime .. endTime)
| where ProcessCommandLine has_any (recon_terms) or FileName has_any (recon_terms)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated desc
```
<img width="2144" height="474" alt="flag4" src="https://github.com/user-attachments/assets/33b5e62a-54d4-42ab-ae05-7084b420484e" />

- **Evidence Collected:** 2025-10-09T12:51:44.3425653Z
- **Final Finding:** Host context enumeration occurred on 2025-10-09.

### Flag 5 – Storage Surface Mapping
- **Objective:** Detect discovery of local/network storage.
- **Hypothesis:** Enumeration of storage locations precedes collection.
- **KQL Query Used:**
```
let storage_terms = dynamic(["get", "wmic"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between (datetime(2025-10-09T12:20:00Z)..datetime(2025-10-09T13:00:00Z))
| where ProcessCommandLine has_any (storage_terms) or FileName has_any (storage_terms)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="2072" height="493" alt="flag5" src="https://github.com/user-attachments/assets/123b9e08-0d1f-4a72-a831-b617aa9f58cf" />

- **Evidence Collected:** `"cmd.exe" /c wmic logicaldisk get name,freespace,size`
- **Final Finding:** Local storage enumeration detected.

### Flag 6 – Connectivity & Name Resolution Check
- **Objective:** Detect outward connectivity and DNS checks.
- **Hypothesis:** Actors validate egress before exfiltration.
- **KQL Query Used:**
```
let net_terms = dynamic(["nslookup","ping","tracert","curl","wget"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:45:00Z) .. datetime(2025-10-09T13:10:00Z))
| where ProcessCommandLine has_any (net_terms) or FileName has_any (net_terms)
| project TimeGenerated, FileName, InitiatingProcessParentFileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```
<img width="2057" height="303" alt="flag6" src="https://github.com/user-attachments/assets/0e8f4bb0-afbc-4172-97ca-e0bd4c8c08e0" />

- **Evidence Collected:** `RuntimeBroker.exe`
- **Final Finding:** Connectivity validation performed via RuntimeBroker.

### Flag 7 – Interactive Session Discovery
- **Objective:** Detect enumeration of active user sessions.
- **Hypothesis:** Actors gather active session info to guide attack timing.
- **KQL Query Used:**
```
let session_terms = dynamic(["qwinsta", "quser", "query user", "query session", "whoami", "session"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:20:00Z)..datetime(2025-10-09T13:10:00Z))
| where ProcessCommandLine has_any (session_terms) or FileName has_any (session_terms)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId
| order by TimeGenerated asc
```
<img width="2507" height="492" alt="flag7" src="https://github.com/user-attachments/assets/dc87acab-2627-428c-8ae9-d2b63a66875d" />

- **Evidence Collected:** `2533274790397065`
- **Final Finding:** PowerShell process uniquely identified for session enumeration.

### Flag 8 – Runtime Application Inventory
- **Objective:** Detect enumeration of running processes/services.
- **Hypothesis:** Process inventory informs potential collection targets.
- **KQL Query Used:**
```
let search_terms = dynamic(["Get-Process", "sc", "Get-Service", "net start", "tasklist"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:20:00Z)..datetime(2025-10-09T14:10:00Z))
| where ProcessCommandLine has_any (search_terms)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="1948" height="490" alt="flag8" src="https://github.com/user-attachments/assets/dff79a90-044a-4ac0-b7a1-b7edc6da8439" />

- **Evidence Collected:** `tasklist.exe`
- **Final Finding:** Runtime application inventory confirmed.

### Flag 9 – Privilege Surface Check
- **Objective:** Detect privilege discovery attempts.
- **Hypothesis:** Mapping privileges informs subsequent escalation strategy.
- **KQL Query Used:**
```
let search_terms = dynamic(["whoami", "net user"]);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:20:00Z)..datetime(2025-10-09T14:10:00Z))
| where ProcessCommandLine has_any (search_terms)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="2016" height="460" alt="flag9" src="https://github.com/user-attachments/assets/6c586b8f-c0e1-4a0b-b5cb-0b9f2473fe82" />

- **Evidence Collected:** 2025-10-09T12:52:14.3135459Z
- **Final Finding:** Privilege enumeration detected via PowerShell.

### Flag 10 – Proof-of-Access & Egress Validation
- **Objective:** Detect outbound reachability validation and host state capture.
- **Hypothesis:** Actors combine network checks with host artifacts before exfiltration.
- **KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:50:00Z)..datetime(2025-10-09T13:00:00Z))
| where FileName contains "support" or FolderPath contains "support"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="1955" height="559" alt="flag10&#39;1" src="https://github.com/user-attachments/assets/dfba1408-3be5-4cba-949d-c5f8022caa21" />

```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:50:00Z)..datetime(2025-10-09T13:00:00Z))
| where ActionType == "ConnectionSuccess" 
| where RemoteIP has "."  
| where RemoteUrl !has "microsoft" and RemoteUrl !has "windows"
| project TimeGenerated, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="2464" height="423" alt="flag10&#39;2" src="https://github.com/user-attachments/assets/1292a5ee-cfa7-4403-913e-67c6b0a4cf6a" />

- **Evidence Collected:** First outbound: `www.msftconnecttest.com`
- **Final Finding:** Outbound reachability confirmed post-artifact creation.

### Flag 11 – Bundling / Staging Artifacts
- **Objective:** Detect consolidation of artifacts for transfer.
- **Hypothesis:** Staging simplifies exfiltration and correlates with prior recon.
- **KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:58:00Z)..datetime(2025-10-09T13:10:00Z))
| where ActionType == "FileCreated" or FileName contains ".zip"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="2418" height="431" alt="flag11" src="https://github.com/user-attachments/assets/6fbcd0a4-1055-47d6-a303-055b7feaf2f4" />

- **Evidence Collected:** `C:\Users\Public\ReconArtifacts.zip`
- **Final Finding:** Malicious artifacts staged for exfiltration.

### Flag 12 – Outbound Transfer Attempt (Simulated)
- **Objective:** Detect attempts to move data off-host.
- **Hypothesis:** Outbound transfer tests reveal egress paths.
- **KQL Query Used:**
```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T13:00:00Z)..datetime(2025-10-09T13:10:00Z))
| where RemoteIP has "."  
| where RemoteUrl !has "microsoft" and RemoteUrl !has "windows"  
| project TimeGenerated, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1873" height="426" alt="flag12" src="https://github.com/user-attachments/assets/0c075bbc-f278-4314-b3ff-faf661671a5d" />

- **Evidence Collected:** `100.29.147.161`
- **Final Finding:** Last outbound connection simulated egress testing.

### Flag 13 – Scheduled Re-Execution Persistence
- **Objective:** Detect mechanisms for repeated execution.
- **Hypothesis:** Scheduled tasks maintain access beyond initial session.
- **KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:50:00Z)..datetime(2025-10-09T13:10:00Z))
| where ProcessCommandLine contains "schtasks" 
   or ProcessCommandLine contains "Register-ScheduledTask"
   or FileName == "schtasks.exe"
| order by TimeGenerated asc
```
<img width="2549" height="279" alt="flag13" src="https://github.com/user-attachments/assets/4e17ea9d-9f4f-4fde-8029-66dbdc7c58d5" />

- **Evidence Collected:** `SupportToolUpdater`
- **Final Finding:** Persistent scheduled task created for ongoing execution.

### Flag 14 – Autorun Fallback Persistence
- **Objective:** Detect lightweight autorun persistence entries.
- **Hypothesis:** Backup autorun entries improve access resilience.
- **KQL Query Used:**
```
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:50:00Z)..datetime(2025-10-09T13:10:00Z))
| order by TimeGenerated asc
```
- **Evidence Collected:** `RemoteAssistUpdater` as query returned no result, so used this instead.
- **Final Finding:** Fallback autorun mechanism identified.

### Flag 15 – Planted Narrative / Cover Artifact
- **Objective:** Identify narrative or misdirection artifacts.
- **Hypothesis:** Text or link files may explain malicious actions falsely.
- **KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between(datetime(2025-10-09T12:50:00Z)..datetime(2025-10-09T13:10:00Z))
| where ActionType == "FileCreated" or ActionType == "FileModified"
| where FileName endswith ".txt" or FileName endswith ".lnk" or FileName endswith ".log"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="2144" height="462" alt="flag15" src="https://github.com/user-attachments/assets/03e19fd4-0bdc-4810-bb10-277e5de23ba1" />

- **Evidence Collected:** `SupportChat_log.lnk`
- **Final Finding:** Planted narrative created as misdirection.

---

## Indicators of Compromise (IoCs)

| IoC Type | Value |
|----------|-------|
| Files | `DefenderTamperArtifact.lnk`, `ReconArtifacts.zip`, `SupportTool.ps1`, `SupportToolUpdater`, `SupportChat_log.lnk` |
| Process | `RuntimeBroker.exe`, `powershell.exe`, `tasklist.exe` |
| Scheduled Task | `SupportToolUpdater` |

---

## MITRE ATT&CK MAPPING

### Phase 1: Initial Compromise (Flag 1)
- **T1059.001**: PowerShell execution with bypassed execution policy

### Phase 2: Defense Evasion & Persistence Setup (Flags 2, 13, 14, 15)
- **T1562.001**: Defense tampering simulation
- **T1053.005**: Scheduled task persistence
- **T1547.001**: Autorun persistence
- **T1036**: Cover artifacts for misdirection

### Phase 3: Comprehensive Discovery (Flags 3-10)
- **T1033**: User/session discovery (Flags 3, 7)
- **T1082**: System information discovery (Flags 4, 9)
- **T1083**: Storage discovery (Flag 5)
- **T1046**: Network discovery (Flag 6)
- **T1057**: Process discovery (Flag 8)
- **T1049**: Network connection discovery (Flag 10)

### Phase 4: Collection & Staging (Flags 3, 11, 12)
- **T1560.001/002**: Data collection and archiving
- **T1074.001**: Local data staging

### Phase 5: Exfiltration Attempts (Flags 10, 12)
- **T1071.001**: C2 communication
- **T1041**: Exfiltration over command channel

---

## Recommendations

1. **Contain & Isolate** affected endpoints to prevent further artifact staging.
2. **Remove Persistent Tasks & Autorun Entries** like `SupportToolUpdater` and `RemoteAssistUpdater`.
3. **Audit Outbound Connections** to suspicious IPs and domains.
4. **Perform Full Artifact Analysis** on staged files for exfiltration impact.
5. **Enhance Monitoring** for rapid data probes and privilege checks.
6. **User Education** on downloading/executing files from untrusted sources.
