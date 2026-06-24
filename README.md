
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

| **Flag** | **Action Observed** | **Key Evidence** |
|----------|---------------------|------------------|
| Flag 1 | The comprmised Principal | `m.smith@lognpacific.org` |
| Flag 2 | The flagged source | `103.69.224.136` |
| Flag 3 | The Client OS | `Linux` |
| Flag 4 | The Stored Detection Type | `anonymizedIPAddress` |
| Flag 5 | Audit the verdict | `dismissed` |
| Flag 6 | Live Exposure| `Enabled` |
| Flag 7 | How the session beat MFA | `singleFactorAuthentication` |
| Flag 8 | The control surface that let them in | `One Outlook Web` |
| Flag 9 | Failed Attempts before entry | `2`|
| Flag 10 | Blast Radius of one token | `7` |
| Flag 11 | One continuous session | `005d431a-380b-1f5e-e554-16d5010dc28e` |
| Flag 12 | MFA-Posture profiling | `userRegistrationDetails` |
| Flag 13 | Group Enumeration | `/v1.0/me/memberOf` |
| Flag 14 | The Fraudulent Request | `Updated Banking Details - Pacific IT Monthly` |
| Flag 15 | The thread they mined | `Q1 Vendor Payment Schedule - Review Required` |
| Flag 16 | The Fraud Target | `j.reynolds@lognpacific.org ` |
| Flag 17 | Second Channel Reinforcement | `Microsoft Teams` |
| Flag 18 | The Concealment Rule | `Invoice Processing` |
| Flag 19 | Whaere the Hidden Mail goes | `Hide replies without alerting the user` |
| Flag 20 | The Exfiltration Rule | `merovingian1337@proton.me` |
| Flag 21 | Who Both Rules Target| `Hide and monitor replies to the fraudulent payment request` |
| Flag 22 | The Exfil Operation | FileDownloaded — distinguished from normal FileAccessed activity because it created a local copy of the file outside Microsoft 365, rather than simply viewing it within the service. |
| Flag 23 | Volume Taken | 3 — the small number of downloads indicates focused exfiltration of specific documents, not opportunistic mass data theft.  |
| Flag 24 | The Credential Document | `VPN-Access-Credentials.txt`|
| Flag 25 | The Vault Pointer | `yomark.pdf` |
| Flag 26 | Disapprove the Innocent Explaination | `0` |
| Flag 27 | Catch the Plant | `Microsoft Flow Portal` |
| Flag 28 | The cause behind the forward | `MicrosoftGraphActivityLogs` |
| Flag 29 | Prove it with the sequence | `Graph Call` |
| Flag 30 | The Automation source IP | `20.150.129.194 ` |
| Flag 31 | The Automation Identity | `7ab7862c-4c57-491e-8a45-d52a7e023983 ` |
| Flag 32 | Name the abused service | `Power Automate` |
| Flag 33 | One Actor, Every Source | `7` |
| Flag 34 | Containment Ordering | `Revoke user sessions` |
| Flag 35 | Where the flow is removed | `Power Platform Admin Center` |
| Flag 36 | The Control that never fired | CA was not applied, so the legacy client bypassed policy.  |
| Flag 37 | Why Revoke before reset | Active refresh tokens survive a password reset; revoke user sessions first. |

---

## Starting Point – Review Incident 87241 in Microsoft Defender XDR to identify the affected user, suspicious sign-in, and initial evidence before pivoting to Sentinel for further investigation.

**Objective:**
Determine whether the suspicious sign-in resulted in a Microsoft 365 account compromise, assess attacker activity and persistence mechanisms, identify potential data exfiltration, and evaluate indicators of Business Email Compromise (BEC).

- **Host of Interest:** `m.smith@lognpacific.org`  
- **Why:** Primary compromised Microsoft 365 identity associated with Incident 87241 and all subsequent malicious activity.
- **Investigation Used:**
```
SigninLogs
	| where UserPrincipalName contains 'm.smith'
	| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
  | project TimeGenerated, UserPrincipalName, IPAddress
	| order by TimeGenerated desc
```
<img width="2041" height="474" alt="Screenshot 2025-11-14 194024" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/1%20and%202.png" />

---

## Flag Analysis

### Flag 1 – The Compromised Principal
- **Objective:** Identify the compromised user account (UPN).
- **Data Source:** SigninLogs
- **Investigation query:**
```
SigninLogs
	| where UserPrincipalName contains 'm.smith'
	| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
  | project TimeGenerated, UserPrincipalName, IPAddress
	| order by TimeGenerated desc
```
<img width="2041" height="474" alt="Screenshot 2025-11-14 194024" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/1%20and%202.png" />
- **Final Finding:** Compromised principal identified `m.smith@lognpacific.org`.

### Flag 2 – The Flagged Source
- **Objective:** Identify the source IP associated with Entra ID risk event.
- **Data Source:** SigninLogs
- **Investigation query:**
```
SigninLogs
	| where UserPrincipalName contains 'm.smith'
	| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
  | project TimeGenerated, UserPrincipalName, IPAddress
	| order by TimeGenerated desc
```
<img width="2041" height="474" alt="Screenshot 2025-11-14 194024" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/1%20and%202.png" />
- **Final Finding:** Source IP identified as `103.69.224.136`.

### Flag 3 – The Client OS
- **Objective:** Identify the operating system used during the suspicious sign-in.
- **Data Source:** SigninLogs
- **Investigation query:**
```
SigninLogs
	| where UserPrincipalName == "m.smith@lognpacific.org"
	| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
	| project TimeGenerated, IPAddress, UserAgent, DeviceDetail, AppDisplayName
  | order by TimeGenerated desc
```
<img width="1500" height="532" alt="flag3" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/3.png" />
- **Final Finding:** The suspicious sign-in originated from a `Linux` client.

### Flag 4 – The Stored Detection Type
- **Objective:** Identify the stored Entra ID risk detection type associated with the suspicious sign-in.
- **Data Source:** AADUserRiskEvents
- **Investigation query:**
```
AADUserRiskEvents
	| where TimeGenerated between (datetime(2026-06-10 23:00:00) .. datetime(2026-06-11 04:00:00))
	| where UserPrincipalName has "m.smith" or IpAddress == "103.69.224.136"
	| project TimeGenerated, UserPrincipalName, IpAddress, RiskEventType, RiskLevel, RiskState
```
<img width="2144" height="474" alt="flag4" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/4.png" />
- **Final Finding:** The Entra ID Protection event classified the suspicious activity as `anonymizedIPAddress`.

### Flag 5 – Audit the verdict
- **Objective:** Determine the final state of the Entra ID risk detections associated with the compromised account.
- **Data Source:** AADUserRiskEvents
- **Investigation query:**
```
AADUserRiskEvents
	| where TimeGenerated between (datetime(2026-06-10 23:00:00) .. datetime(2026-06-11 04:00:00))
	| where UserPrincipalName has "m.smith" or IpAddress == "103.69.224.136"
	| project TimeGenerated, UserPrincipalName, IpAddress, RiskEventType, RiskLevel, RiskState
```
<img width="2144" height="474" alt="flag4" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/4.png" />
- **Final Finding:** The risk detection associated with the compromised account was in the `Dismissed` state.

### Flag 6 – Live Exposure
- **Objective:** Determine the status of the compromised user account from the incident asset.
- **Data Source:** Microsoft Defender XDR Incident Asset
<img width="2057" height="303" alt="flag6" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/6.png" />
- **Final Finding:** The compromised user account was in an `Enabled` state at the time of the investigation.

### Flag 7 – How the Session beat MFA
- **Objective:** Identify the authentication method that allowed the attacker to access the account despite MFA enforcement.
- **Data Source:** SigninLogs
- **Investigation query:**
```
SigninLogs 
  | where IPAddress == "103.69.224.136" and UserPrincipalName contains "m.smith" 
	| where ResultSignature == 'SUCCESS'
	| project TimeGenerated, UserPrincipalName, IPAddress,AuthenticationRequirement, ConditionalAccessStatus 
  | order by TimeGenerated asc
```
<img width="2507" height="492" alt="flag7" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/7.png" />
- **Final Finding:**  The successful sign-in used `singleFactorAuthentication`, indicating the session bypassed an additional MFA challenge despite tenant-wide MFA enforcement.

### Flag 8 – Control surface that let them in
- **Objective:** Identify the application through which the attacker successfully authenticated.
- **Data Source:** SigninLogs
- **Investigation query:**
```
	SigninLogs
	| where IPAddress == "103.69.224.136" and UserPrincipalName contains "m.smith"
	| where ResultSignature == 'SUCCESS'
	| project TimeGenerated, UserPrincipalName, IPAddress,AuthenticationRequirement, AppDisplayName
  | order by TimeGenerated asc
```
<img width="1948" height="490" alt="flag8" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/8.png" />
- **Final Finding:** The first successful sign-in occurred through `One Outlook Web`.

### Flag 9 – Failed Attempts before Entry.
- **Objective:** Determine the number of failed password attempts from the attacker IP before the successful sign-in.
- **Data Source:** SigninLogs
- **Investigation query:**
```
	SigninLogs
	| where IPAddress == "103.69.224.136" and AlternateSignInName == "m.smith@lognpacific.org"
	| where AppDisplayName contains "One Outlook Web"
  | project TimeGenerated,Identity, ResultSignature
```
<img width="2016" height="460" alt="flag9" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/9.png" />
- **Final Finding:** `Two` bad-password attempts were observed before the successful sign-in.

### Flag 10 – Blast Radius of one token
- **Objective:** Determine how many Microsoft 365 applications were accessed using the compromised session.
- **Data Source:** SigninLogs
- **Investigation query:**
```
	SigninLogs
	| where IPAddress == "103.69.224.136" and UserPrincipalName contains "m.smith"
	| where ResultSignature == 'SUCCESS'
	| where TimeGenerated >= datetime(2026-06-10 23:16:05)
  | summarize DistinctApps=dcount(AppDisplayName)
```
<img width="1955" height="559" alt="flag10&#39;1" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/10.png" />
- **Final Finding:** `Seven` distinct Microsoft 365 applications were accessed after the first successful sign-in, demonstrating the scope of activity enabled by the compromised session. 

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
