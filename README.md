
# Threat Hunt Report: Second Vector

**Analyst:** Akshita Shah

**Date Completed:** 2026-06-23  

**Environment Investigated:** law-cyber-range 

**Timeframe:** 2026-06-11 03:00 UTC - 2026-06-11 13:00 UTC

**Status:** Inherited from night shift

---

## Executive Summary

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
  
## Timeline of Events

| **TimeGenerated (UTC)**    | **Action Observed**                                               | **Evidence**                                   | **Flag** |
| -------------------------- | ----------------------------------------------------------------- | ---------------------------------------------- | :------: |
| 2026-06-10 **11:16:05 PM** | Successful sign-in identified the compromised user.               | `m.smith@lognpacific.org`                      |   **Flag 1**  |
| 2026-06-10 **11:15:23 PM** | Suspicious source IP observed.                                    | `103.69.224.136`                               |   **Flag 2**  |
| 2026-06-10 **11:16:05 PM** | Client operating system identified.                               | `Linux`                                        |   **Flag 3**  |
| 2026-06-10 **11:16:05 PM** | Entra ID risk detection identified.                               | `anonymizedIPAddress`                          |   **Flag 4**  |
| 2026-06-10 **11:16:05 PM** | Risk detections were dismissed.                                   | `Dismissed`                                    |   **Flag 5**  |
|  *(Incident Asset)*     	 | Account status verified in Defender XDR.                          | `Enabled`                                      |   **Flag 6**  |
| 2026-06-10 **11:16:05 PM** | Authentication requirement identified.                            | `singleFactorAuthentication`                   |   **Flag 7**  |
| 2026-06-10 **11:16:05 PM** | First successful application accessed.                            | `One Outlook Web`                              |   **Flag 8**  |
| 2026-06-10 **11:15:45 PM** | Failed password attempts before successful sign-in.               | `2 attempts`                                   |   **Flag 9**  |
| 2026-06-10 **11:16:05 PM** | Number of Microsoft 365 applications accessed during the session. | `7 applications`                               |  **Flag 10**  |
| 2026-06-10 **11:16:05 PM** | Authenticated session identifier established.                     | `005d431a-380b-1f5e-e554-16d5010dc28e`         |  **Flag 11**  |
| 2026-06-10 **11:09:37 PM** | Microsoft Graph profiled the user's MFA posture.                  | `userRegistrationDetails`                      |  **Flag 12**  |
| 2026-06-10 **11:09:36 PM** | Microsoft Graph enumerated group memberships.                     | `/v1.0/me/memberOf`                            |  **Flag 13**  |
| 2026-06-11 **08:40:49 AM** | Fraudulent payment email identified.                              | `Updated Banking Details - Pacific IT Monthly` |  **Flag 14**  |
| 2026-06-10 **11:13:30 PM** | Historical payment approval emails accessed.                      | `Q1 Vendor Payment Schedule - Review Required` |  **Flag 15**  |
| 2026-06-11 **08:40:49 AM** | Fraud target identified.                                          | `j.reynolds@lognpacific.org`                   |  **Flag 16**  |
| 2026-06-10 **11:40:04 PM** | Secondary communication channel accessed.                         | `Microsoft Teams`                              |  **Flag 17**  |
| 2026-06-10 **11:28:22 PM** | Malicious inbox rule created.                                     | `Invoice Processing`                           |  **Flag 18**  |
| 2026-06-10 **11:28:22 PM** | Inbox rule archived victim replies.                               | `Archive folder`                               |  **Flag 19**  |
| 2026-06-10 **11:32:31 PM** | External forwarding rule created.                                 | `merovingian1337@proton.me`                    |  **Flag 20**  |
| 2026-06-10 **11:28:22 PM** | Both inbox rules targeted the fraud recipient.                    | `j.reynolds@lognpacific.org`                   |  **Flag 21**  |
| 2026-06-10 **11:37:22 PM** | Data exfiltration through file download detected.                 | `FileDownloaded`                               |  **Flag 22**  |
| 2026-06-10 **11:37:22 PM** | Number of files downloaded during the session.                    | `3 files`                                      |  **Flag 23**  |
| 2026-06-10 **11:37:22 PM** | Sensitive credential document downloaded.                         | `VPN-Access-Credentials.txt`                   |  **Flag 24**  |
| 2026-06-10 **11:39:12 PM** | Credential-related document accessed.                             | `yomark.pdf`                                   |  **Flag 25**  |
| 2026-06-10 **11:16:05 PM** | Successful MFA challenges observed.                               | `0`                                            |  **Flag 26**  |
| 2026-06-10 **11:46:32 PM** | Automation platform accessed.                                     | `Microsoft Flow Portal`                        |  **Flag 27**  |
| 2026-06-11 **08:41:09 AM** | Graph activity confirmed automated email forwarding.              | `Graph /forward request`                       |  **Flag 28**  |
| 2026-06-11 **08:41:09 AM** | Graph API request executed before forwarded email.                | `Graph Call → Mail Event`                      |  **Flag 29**  |
| 2026-06-11 **08:41:09 AM** | Automation workflow source IP identified.                         | `20.150.129.194`                               |  **Flag 30**  |
| 2026-06-11 **08:41:09 AM** | Automation application ID identified.                             | `7ab7862c-4c57-491e-8a45-d52a7e023983`         |  **Flag 31**  |
| 2026-06-10 **11:46:32 PM** | Service used for automated forwarding identified.                 | `Power Automate`                               |  **Flag 32**  |
| Throughout Investigation   | Attacker IP correlated across telemetry sources.                  | `7 log sources`                                |  **Flag 33**  |
| Investigation Finding      | First containment action identified.                              | `Revoke user sessions`                         |  **Flag 34**  |
| Investigation Finding      | Administrative console used to remove malicious flow.             | `Power Platform Admin Center`                  |  **Flag 35**  |
| Investigation Finding      | Conditional Access evaluation reviewed.                           | `Not Applied`                                  |  **Flag 36**  |
| Investigation Finding      | Password reset sequencing determined.                             | `Revoke sessions before password reset`        |  **Flag 37**  |


---

## Starting Point – Review Incident 87241 in Microsoft Defender XDR

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

## Stage 1 – Initial Access & Identity Validation (Flags 1–10)

### Flag 1 – The Compromised Principal
- **Objective:** Identify the compromised user account (UPN).
- **Data Source:** SigninLogs
- **KQL Query Used:**
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
- **KQL Query Used:**
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
- **KQL Query Used:**
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
- **KQL Query Used:**
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
- **KQL Query Used:**
```
AADUserRiskEvents
	| where TimeGenerated between (datetime(2026-06-10 23:00:00) .. datetime(2026-06-11 04:00:00))
	| where UserPrincipalName has "m.smith" or IpAddress == "103.69.224.136"
	| project TimeGenerated, UserPrincipalName, IpAddress, RiskEventType, RiskLevel, RiskState
```
<img width="2144" height="474" alt="flag4" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/4.png" />

- **Final Finding:** The majority of Entra ID risk detections associated with the compromised account were in the `Dismissed` state.
  
### Flag 6 – Live Exposure
- **Objective:** Determine the status of the compromised user account from the incident asset.
- **Data Source:** Microsoft Defender XDR Incident Asset
<img width="2057" height="303" alt="flag6" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/6.png" />

- **Final Finding:** The compromised user account was in an `Enabled` state at the time of the investigation.

### Flag 7 – How the Session beat MFA
- **Objective:** Identify the authentication method that allowed the attacker to access the account despite MFA enforcement.
- **Data Source:** SigninLogs
- **KQL Query Used:**
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
- **KQL Query Used:**
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
- **KQL Query Used:**
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
- **KQL Query Used:**
```
SigninLogs
	| where IPAddress == "103.69.224.136" and UserPrincipalName contains "m.smith"
	| where ResultSignature == 'SUCCESS'
	| where TimeGenerated >= datetime(2026-06-10 23:16:05)
  	| summarize DistinctApps=dcount(AppDisplayName)
```
<img width="1955" height="559" alt="flag10&#39;1" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/10.png" />

- **Final Finding:** `Seven` distinct Microsoft 365 applications were accessed after the first successful sign-in, demonstrating the scope of activity enabled by the compromised session. 

## Stage 2 – Reconnaissance (Flags 11–17)

### Flag 11 – One Continuous session
- **Objective:** Identify the session identifier used to correlate the initial sign-in with subsequent attacker activity across multiple data sources.
- **Data Source:** SigninLogs and CloudAppEvents 
- **KQL Query Used:**
```
SigninLogs
	| where UserPrincipalName has "m.smith" and IPAddress == "103.69.224.136"
	| where ResultSignature == 'SUCCESS'
	| project TimeGenerated, Identity, SessionId
```
<img width="2418" height="431" alt="flag11" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/11.png" />

- For cross checking in CloudAppEvents
```
CloudAppEvents
	| extend SessionId = tostring(RawEventData.SessionId)
	| where SessionId == "005d431a-380b-1f5e-e554-16d5010dc28e"
	| project TimeGenerated, AccountDisplayName, SessionId, IPAddress 
```
<img width="2418" height="431" alt="flag11" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/11.2.png" />

- **Final Finding:** Session ID `005d431a-380b-1f5e-e554-16d5010dc28e` was present in both SigninLogs and CloudAppEvents, confirming that the observed activities belonged to the same authenticated session.
  
### Flag 12 – MFA Posture profiling
- **Objective:** Identify the user's registered authentication methods and MFA posture.
- **Data Source:** MicrosoftGraphActivityLogs
- **KQL Query Used:**
```
MicrosoftGraphActivityLogs
	| where IPAddress == "103.69.224.136"
	| where RequestUri has "reports"
	| where TimeGenerated >= datetime(2026-06-10 23:16:05)
	| project TimeGenerated, RequestUri, UserAgent, SessionId
	| order by TimeGenerated asc
```
<img width="1873" height="426" alt="flag12" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/12.png" />

- **Final Finding:** The attacker queried the `userRegistrationDetails` resource to identify the user's registered authentication methods and overall MFA posture.

### Flag 13 – Group Enumeration
- **Objective:** Identify the Microsoft Graph API request used to enumerate the victim's group memberships.
- **Data Source:** MicrosoftGraphActivityLogs
- **KQL Query Used:**
```
MicrosoftGraphActivityLogs
	| where IPAddress == "103.69.224.136"
	| where RequestUri has "memberOf"
	| project TimeGenerated, RequestUri
	| order by TimeGenerated asc
```
<img width="2549" height="279" alt="flag13" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/13.png" />

- **Final Finding:** The attacker used `/v1.0/me/memberOf` to enumerate the victim's Microsoft Entra group memberships.
  
### Flag 14 – Fraudulent Request
- **Objective:** Identify the subject of the fraudulent payment redirection email.
- **Data Source:** EmailEvents
- **KQL Query Used:**
```
EmailEvents
	| where RecipientEmailAddress == "m.smith@lognpacific.org" and Subject contains "bank"
	| project TimeGenerated, RecipientEmailAddress, Subject, DeliveryAction
```
<img width="2549" height="279" alt="flag13" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/14.png" />

- **Final Finding:** The fraudulent payment redirection email used the subject `Updated Banking Details - Pacific IT Monthly`

### Flag 15 – Thread they mined
- **Objective:** Identify the historical payment-related email thread reviewed during reconnaissance.
- **Data Source:** OfficeActivity
- **KQL Query Used:**
```
OfficeActivity
	| where Operation == "MailItemsAccessed" and UserId == "m.smith@lognpacific.org"
	| mv-expand Folder = parse_json(Folders)
	| mv-expand Item = Folder.FolderItems
	| extend Subject=tostring(Item.Subject)
	| where Subject has_any ("payment", "approval", "approve", "invoice", "wire", "vendor", "transfer")
	| project TimeGenerated,Subject, Client_IPAddress
```
<img width="2144" height="462" alt="flag15" src="https://github.com/user-attachments/assets/03e19fd4-0bdc-4810-bb10-277e5de23ba1" />

- **Final Finding:** The attacker reviewed the thread `Q1 Vendor Payment Schedule - Review Required` to understand the organization's payment approval workflow before initiating fraud.

### Flag 16 – The Fraud Target
- **Objective:** Identify the recipient of the fraudulent payment redirection email.
- **Data Source:** EmailEvents
- **KQL Query Used:**
```
EmailEvents
	| where RecipientEmailAddress == "m.smith@lognpacific.org" and Subject contains "bank"
	| project TimeGenerated, RecipientEmailAddress, Subject, SenderMailFromAddress 
```
<img width="2507" height="492" alt="flag7" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/16.png" />

- **Final Finding:**  The fraudulent payment request was sent to `j.reynolds@lognpacific.org`
  
### Flag 17 – Second Channel Reinforcement
- **Objective:** Identify the secondary communication channel used to reinforce the fraudulent payment request.

- **Final Finding:** The attacker used `Microsoft Teams` as a secondary communication channel to reinforce the fraudulent payment request.

## Stage 3 – Persistence & Business Email Compromise (Flags 18–21)

### Flag 18 – Concealment rule
- **Objective:** Identify the mailbox rule created to conceal payment-related communications.
- **Data Source:** OfficeActivity
- **KQL Query Used:**
```
OfficeActivity
	| where UserId == "m.smith@lognpacific.org"
	| where Operation contains "Rule"
	| project TimeGenerated, Operation, Parameters, UserId
	| order by TimeGenerated asc
```
<img width="2016" height="460" alt="flag9" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/18.png" />

- **Final Finding:** A malicious inbox rule named `Invoice Processing` was created to hide payment-related communications.

### Flag 19 – Where the hidden mail goes 
- **Objective:** Determine why the attacker archived payment-related emails instead of deleting them.
- **Data Source:** OfficeActivity (Inbox Rule Analysis)

- **Final Finding:** The rule moved payment-related emails to the Archive folder instead of deleting them, allowing the attacker to `hide legitimate replies without alerting the user` while maintaining access to the conversation.

### Flag 20 – Exfiltration Rule
- **Objective:** Identify the external email address configured in the malicious forwarding rule.
- **Data Source:** OfficeActivity   
- **KQL Query Used:**
```
OfficeActivity
	| where UserId == "m.smith@lognpacific.org"
	| where Operation contains "Rule"
	| project TimeGenerated, Operation, Parameters, UserId
	| order by TimeGenerated asc
```
<img width="2418" height="431" alt="flag11" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/20.png" />

- **Final Finding:** The malicious forwarding rule redirected emails to `merovingian1337@proton.me`
  
### Flag 21 – Who both rules target
- **Objective:** Determine why the attacker targeted emails from j.reynolds@lognpacific.org using both malicious inbox rules.

- **Final Finding:** The inbox rules were designed to `hide and monitor replies to the fraudulent payment request`. By moving emails to the Archive folder and forwarding copies to an external ProtonMail account, the attacker concealed legitimate responses from the victim while continuing to monitor the conversation.

## Stage 4 – Data Exfiltration (Flags 22–25)
  
### Flag 22 – The Exfil operation
- **Objective:** Identify the operation that indicates files were copied out of Microsoft 365 rather than viewed within the service.
- **Data Source:** OfficeActivity
- **KQL Query Used:**
```
OfficeActivity
	| where UserId == "m.smith@lognpacific.org"
	| where OfficeWorkload in ("SharePoint", "OneDrive")
	| summarize count() by Operation
	| order by count_ desc
```
<img width="365" height="237" alt="image" src="https://github.com/user-attachments/assets/b777b12a-b568-48dc-b338-1a70f2a303e8" />


- **Final Finding:** The attacker used the `FileDownloaded` operation to copy files from SharePoint and OneDrive to the local device. Unlike FileAccessed, which only records files being viewed within Microsoft 365, FileDownloaded indicates that a local copy of the file was created, making it evidence of data exfiltration.
  
### Flag 23 – Volume Taken
- **Objective:** Determine the number of files downloaded and assess whether the activity indicated targeted or bulk data theft.
- **Data Source:** OfficeActivity
- **KQL Query Used:**
```
OfficeActivity
	| where UserId == "m.smith@lognpacific.org"
	| where OfficeWorkload in ("SharePoint", "OneDrive")
	| summarize count() by Operation
	| order by count_ desc
```
<img width="365" height="237" alt="image" src="https://github.com/user-attachments/assets/5fb748a0-a536-4807-8e70-69c2643e6c94" />


- **Final Finding:** `3 — the small number of downloads indicates focused exfiltration of specific documents, not opportunistic mass data theft`.

### Flag 24 – Credential Document
- **Objective:** Identify the downloaded file that expanded the scope of the compromise beyond the Microsoft 365 mailbox.
- **Data Source:** OfficeActivity
- **KQL Query Used:**
```
OfficeActivity
	| where Operation == "FileDownloaded"
	| where UserId == "m.smith@lognpacific.org"
	| project TimeGenerated, SourceFileName, SourceRelativeUrl, Site_Url, UserId
	| order by TimeGenerated asc
```
<img width="2549" height="279" alt="flag13" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/24.png" />

- **Final Finding:** The downloaded credential-related document was `VPN-Access-Credentials.txt`. Its presence indicates the attacker may have obtained credentials capable of providing access beyond the compromised Microsoft 365 account, increasing the risk of broader network compromise.
  
### Flag 25 – Vault Pointer
- **Objective:** Determine which accessed file indicated the attacker was searching for additional credential resources without performing a file download.
- **Data Source:** OfficeActivity
- **KQL Query Used:**
```
OfficeActivity
	| where Operation == "FileAccessed"
	| where UserId == "m.smith@lognpacific.org"
	| project TimeGenerated, SourceFileName, SourceRelativeUrl, Site_Url, UserId
	| order by TimeGenerated asc

```
<img width="2549" height="279" alt="flag13" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/25.png" />

- **Final Finding:** The attacker accessed `yomark.pdf` without downloading it. Based on the investigation context, the document served as a pointer to a credential store, indicating the attacker was identifying additional credential resources while minimizing file downloads.

## Stage 5 – Automation & Power Automate Abuse (Flags 26–33)

### Flag 26 – Disapprove the innocent explaination
- **Objective:** Determine whether a successful MFA challenge occurred during the compromised session.
- **Data Source:** SigninLogs
- **KQL Query Used:**
```
SigninLogs 
	| where IPAddress == "103.69.224.136" and UserPrincipalName contains "m.smith" 
	| where ResultSignature == 'SUCCESS'
	| project TimeGenerated, UserPrincipalName, IPAddress,AuthenticationRequirement, ConditionalAccessStatus 
	| order by TimeGenerated asc
```
<img width="2507" height="492" alt="flag7" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/7.png" />

- **Final Finding:** `No successful` MFA challenges were observed during the compromised session (0), indicating the attacker relied on an existing authenticated session rather than completing a new MFA prompt. 

### Flag 27 – Catch the plant
- **Objective:** Identify the Microsoft 365 application used to create automation during the compromised session.
- **Data Source:** SigninLogs
- **KQL Query Used:**
```
SigninLogs
	| where UserPrincipalName == "m.smith@lognpacific.org"
	| where IPAddress == "103.69.224.136"
	| where ResultSignature == 'SUCCESS'
	| project TimeGenerated, AppDisplayName, ResourceDisplayName, SessionId
	| order by TimeGenerated asc
```
<img width="2507" height="492" alt="flag7" src="<img width="960" height="192" alt="image" src="https://github.com/user-attachments/assets/e6afa956-1b52-4def-9ae8-7445cf477f35" />
" />

- **Final Finding:** The attacker accessed `Microsoft Flow Portal`, the Microsoft 365 service used to create and manage Power Automate workflows, indicating preparation for automated persistence.

### Flag 28 – Cause behind the forward
- **Objective:** Identify the telemetry source that recorded the automated email forwarding action.
- **Data Source:** MicrosoftGraphActivityLogs
- **KQL Query Used:**
```
MicrosoftGraphActivityLogs
	| where UserAgent has_any ("microsoft-flow", "azure-logic-apps")
	| project TimeGenerated, RequestUri, UserAgent
	| order by TimeGenerated asc
```
<img width="2507" height="492" alt="flag7" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/28.png" />

- **Final Finding:** `MicrosoftGraphActivityLogs`

### Flag 29 – Prove it with the sequence
- **Objective:** Determine whether the Microsoft Graph call or the mail event occurred first.
- 
- **Final Finding:** The Microsoft `Graph call` occurred first, initiating the email forward. The corresponding mail event was generated afterward to record the resulting message.

  ### Flag 30 – Automation Source IP
- **Objective:** Identify the source IP address that executed the automated email forwarding request.
- **Data Source:** MicrosoftGraphActivityLogs
- **KQL Query Used:**
```
MicrosoftGraphActivityLogs
	| where UserAgent has_any ("microsoft-flow", "azure-logic-apps") and RequestUri contains "forward"
	| project TimeGenerated, IPAddress, UserAgent, RequestUri
	| order by TimeGenerated asc
```
<img width="2507" height="492" alt="flag7" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/30.png" />

- **Final Finding:** The automated forwarding request originated from `20.150.129.194`, an Azure Logic Apps / Microsoft Flow infrastructure IP, indicating the action was executed through Power Automate rather than directly from the user's device.

### Flag 31 – Automation Identity
- **Objective:** Identify the application ID associated with the automated Microsoft Graph forwarding request.
- **Data Source:** MicrosoftGraphActivityLogs
- **KQL Query Used:**
```
MicrosoftGraphActivityLogs
	| where UserAgent has_any ("microsoft-flow", "azure-logic-apps") and RequestUri contains "forward"
	| project TimeGenerated, IPAddress, UserAgent, RequestUri, AppId
 | order by TimeGenerated asc

```
<img width="2507" height="492" alt="flag7" src="https://github.com/ShahAkshita31/Cyber-Range-Threat-Hunt-June-26/blob/main/evidence/31.png" />

- **Final Finding:** The automated Microsoft Graph forwarding request was executed using application ID `7ab7862c-4c57-491e-8a45-d52a7e023983`.

### Flag 32 – Name the abused service
- **Objective:** Identify the Microsoft 365 service responsible for the automated email forwarding activity.

- **Final Finding:** The forwarding activity was attributed to `Power Automate`. Evidence included sign-ins to Microsoft Flow Portal and Microsoft Graph /forward requests executed by the microsoft-flow and azure-logic-apps user agents, confirming the email was forwarded through an automated workflow rather than directly by the user.

### Flag 33 – One actor, every source
- **Objective:** Determine how many distinct telemetry sources contained evidence of the attacker IP address.
- **Data Source:** Multiple Microsoft Sentinel tables (search operator)
- **KQL Query Used:**
```
	let IP = "103.69.224.136";
	search IP
	| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20 23:59:59))
	| summarize by $table
```
<img width="467" height="446" alt="33" src="https://github.com/user-attachments/assets/c255bd64-2d59-4697-946b-8a6ff1b6c583" />


- **Final Finding:** The attacker IP appeared across `seven` distinct tables, demonstrating consistent evidence of activity throughout the investigation.

## Stage 6 – Containment & Remediation (Flags 34–37)

### Flag 34 – Containment Ordering
- **Objective:** Identify the first containment action required before removing attacker persistence mechanisms.
  
- **Final Finding:** User sessions should be revoked before removing malicious inbox rules or Power Automate flows. `Revoke User sessions` invalidates the attacker's active tokens, preventing them from recreating persistence mechanisms before access is removed.
	

### Flag 35 – Where the flow is removed
- **Objective:** Identify the administrative console used to manage and remove the malicious Power Automate workflow.

- **Final Finding:** The malicious workflow must be removed through the `Power Platform Admin Center`, where Power Automate flows are managed at the tenant level. Evidence of its use included Microsoft Flow Portal sign-ins and Microsoft Graph /forward requests executed by microsoft-flow and azure-logic-apps user agents.


### Flag 36 – Control that never fired
- **Objective:** Determine why Conditional Access failed to prevent the suspicious sign-in.

- **Final Finding:** `Conditional Access was not applied` to the suspicious sign-ins. Because the policy was never evaluated, the attacker authenticated through a legacy single-factor authentication path that `bypassed` the MFA and risk-based controls normally enforced by Conditional Access.

### Flag 37 – Why revoke before reset
- **Objective:** Determine why revoking user sessions should take precedence over resetting the compromised account password.

- **Final Finding:** A password reset alone does not immediately terminate existing refresh tokens or authenticated sessions. `User sessions should be revoked first to invalidate active tokens` and force reauthentication before resetting credentials.

---

## Indicators of Compromise (IoCs)

| **IoC Type**                | **Value**                                      |
| --------------------------- | ---------------------------------------------- |
| Compromised User            | `m.smith@lognpacific.org`                      |
| Attacker IP                 | `103.69.224.136`                               |
| Automation IP               | `20.150.129.194`                               |
| Session ID                  | `005d431a-380b-1f5e-e554-16d5010dc28e`         |
| Malicious Inbox Rule        | `Invoice Processing`                           |
| External Forwarding Address | `merovingian1337@proton.me`                    |
|Fraud Target	              | `j.reynolds@lognpacific.org`                   |
|Sensitive Files	          | `VPN-Access-Credentials.txt, yomark.pdf`       |

---

## MITRE ATT&CK Mapping

### Phase 1: Initial Access & Credential Abuse (Flags 1–11)
- **T1078.004**: Valid Accounts – Cloud Accounts
- **T1110.001**: Password Guessing (failed authentication attempts before successful sign-in)
- **T1078**: Use of valid credentials to establish an authenticated Microsoft 365 session

### Phase 2: Cloud Reconnaissance (Flags 12–17)
- **T1526**: Cloud Service Discovery (Microsoft Graph reconnaissance)
- **T1087.004**: Account Discovery – Cloud Account (group membership enumeration)
- **T1087**: Account Discovery
- **T1082**: System Information Discovery (tenant and authentication posture profiling)
- **T1589.001**: Gather Victim Identity Information (payment contacts and business relationships)

### Phase 3: Business Email Compromise & Persistence (Flags 18–21)
- **T1114.003**: Email Collection – Email Forwarding Rule
- **T1098**: Account Manipulation (mailbox rule creation)
- **T1078.004**: Valid Accounts – Cloud Accounts (continued use of compromised account)
- **T1566.003**: Phishing – Spearphishing via Service (Microsoft Teams used to reinforce fraud)

### Phase 4: Data Collection & Exfiltration (Flags 22–25)
- **T1213**: Data from Information Repositories (SharePoint and OneDrive)
- **T1530**: Data from Cloud Storage
- **T1005**: Data from Local System (credential-related documents)
- **T1039**: Data from Network Shared Drive

### Phase 5: Power Automate Abuse & Cloud Automation (Flags 26–33)
- **T1059.007**: Command and Scripting Interpreter – JavaScript/API execution (Microsoft Graph API)
- **T1106**: Native API (Microsoft Graph API abuse)
- **T1648**: Serverless Execution (Azure Logic Apps / Power Automate workflow)
- **T1114.003**: Email Forwarding Rule (automated forwarding through Power Automate)

### Phase 6: Defense Evasion & Response (Flags 34–37)
- **T1078.004**: Valid Accounts – Cloud Accounts (active refresh token abuse)
- **T1550.001**: Use of Web Session Cookie / Existing Authenticated Session (continued access through valid session tokens)
- **T1562**: Impair Defenses (Conditional Access not applied, allowing legacy authentication path)

---

## Lesson Learned

1. `Low-severity identity alerts` can indicate a full account compromise.
2. Correlating multiple `Microsoft 365 log sources` is critical for cloud investigations.
3. `Microsoft Graph API` activity provides valuable attacker visibility.
4. `Power Automate` and `mailbox rules` can be abused for persistence.
5. `Session revocation` should precede `password resets` during containment.

## Recommendations

1. `Enforce Conditional Access` policies and `block legacy authentication` to prevent MFA bypass.
2. Monitor Microsoft Graph API activity, mailbox rules, and Power Automate workflows for suspicious behavior.
3. Configure alerts for external email forwarding and unauthorized inbox rule creation.
4. `Monitor SharePoint and OneDrive` for `unusual downloads` of sensitive business documents.
5. `Revoke active user sessions immediately` during account compromise `before resetting user credentials`.
