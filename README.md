# Threat Hunt Report: The Great Admin Heist Investigation

**Participant:** Tracey Buentello
**Date:** May 2025

---

## Platforms and Languages Leveraged

### Platforms:

* Microsoft Defender for Endpoint (MDE)
* Log Analytics Workspace
* Windows 10-based corporate workstation (`anthony-001`)

### Languages/Tools:

* Kusto Query Language (KQL) for querying device events, registry modifications, and persistence artifacts
* Native Windows utilities: `powershell.exe`, `cmd.exe`, `schtasks.exe`, `csc.exe`

---

## Scenario

At Acme Corp, the privileged IT admin **Bubba Rockerfeatherman III** unknowingly became the target of a sophisticated APT group called **The Phantom Hackers**. These attackers leveraged phishing and stealthy execution tactics—masquerading malware, abusing Windows LOLBins, and deploying multiple persistence techniques—to breach the system and maintain long-term access.

---

## Key Observations

* **Initial Vector:** A fake antivirus binary named `BitSentinelCore.exe` was dropped into `C:\ProgramData\`.
* **Dropper Used:** Legitimate Microsoft-signed binary `csc.exe` (C# compiler) was abused to compile and drop the malware.
* **Execution:** The malware was executed via PowerShell on `2025-05-07T02:00:36.794406Z`, marking the root of the malicious chain.
* **Keylogger:** A deceptive shortcut `systemreport.lnk` was dropped in the Startup folder to enable keystroke capture on logon.
* **Registry Persistence:** Auto-run registry key was created at:
  `HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
* **Scheduled Task:** Named `UpdateHealthTelemetry`, this ensured long-term execution of the malware.
* **Process Chain:** `BitSentinelCore.exe -> cmd.exe -> schtasks.exe`

---

## Timeline & Queries Used

### Initial Malware Execution

Analyzed `DeviceLogonEvents` on the target system `anthony-001` to determine breach timing. Multiple failed logons were followed by a successful logon from a Philippine IP.

```kql
DeviceLogonEvents
| where DeviceName contains "anthony-001"
```
<img width="1481" alt="Screenshot 2025-05-17 at 4 35 50 PM" src="https://github.com/user-attachments/assets/7d261b74-201e-4720-941d-07ee3f0c1d09" />

📌 **Timestamp:** `2025-05-07T02:00:36.794406Z`

### File Write via Legitimate LOLBin

Filtered file creation events to detect malware deployment. Found `BitSentinelCore.exe` dropped via `csc.exe`.

```kql
DeviceFileEvents
| where FileName == "BitSentinelCore"
```

📌 **Dropper Used:** `csc.exe`

### Execution Path

Validated execution via `DeviceProcessEvents`, showing Bubba manually executed `BitSentinelCore.exe`.

```kql
DeviceProcessEvents
| where FileName == "BitSentinelCore.exe" or InitiatingProcessFileName == "BitSentinelCore.exe"
```
<img width="1506" alt="Screenshot 2025-05-17 at 4 39 19 PM" src="https://github.com/user-attachments/assets/bfacd9a3-5255-4793-ae3e-f8d636f3f82e" />

### Keylogger Artifact

Tracked file creation shortly after initial execution. Identified `systemreport.lnk` as the likely logging mechanism.

```kql
DeviceFileEvents
| where DeviceName contains "anthony-001"
| where Timestamp >= datetime("2025-05-07T02:00:36.794406Z")
```
<img width="1489" alt="Screenshot 2025-05-17 at 4 41 08 PM" src="https://github.com/user-attachments/assets/40eb8616-a7ea-440c-a17a-19c677aa3045" />

📌 **Artifact:** `systemreport.lnk`

### Registry Persistence

Discovered persistence key for auto-run configuration in the current user context.

```kql
DeviceRegistryEvents
| where RegistryKey contains "Run"
| where RegistryValueData has "BitSentinelCore"
```
<img width="1495" alt="Screenshot 2025-05-17 at 4 42 27 PM" src="https://github.com/user-attachments/assets/0ea38513-9162-4e3e-8725-abf316061068" />

📌 **Key:** `HKCU\...\Run`

### Scheduled Task Creation

Detected scheduled task creation with a legitimate-sounding name for long-term persistence.

```kql
DeviceProcessEvents
| where DeviceName contains "anthony"
| where ProcessCommandLine has "BitSentinelCore"
```
<img width="1476" alt="Screenshot 2025-05-17 at 4 44 19 PM" src="https://github.com/user-attachments/assets/f8ebbff4-54c2-42c3-84c8-75a4259882c2" />

📌 **Task Name:** `UpdateHealthTelemetry`

### Process Chain

Confirmed the full execution path:
📌 `BitSentinelCore.exe -> cmd.exe -> schtasks.exe`

---

## Summary of Findings

| Flag | Description                   | Answer/Value                                     |
| ---- | ----------------------------- | ------------------------------------------------ |
| 1    | Fake AV binary                | `BitSentinelCore.exe`                            |
| 2    | Dropper used to write malware | `csc.exe`                                        |
| 3    | Initial execution method      | `BitSentinelCore.exe`                            |
| 4    | Keylogger file dropped        | `systemreport.lnk`                               |
| 5    | Registry persistence path     | `HKEY_CURRENT_USER\...\Run`                      |
| 6    | Scheduled task name           | `UpdateHealthTelemetry`                          |
| 7    | Process chain                 | `BitSentinelCore.exe -> cmd.exe -> schtasks.exe` |
| 8    | Root cause timestamp          | `2025-05-07T02:00:36.794406Z`                    |

---

## Response Actions

* **Immediate Block:** Hashes and process signatures of `BitSentinelCore.exe` added to threat blocklists.
* **Persistence Removal:** Startup `.lnk` file, registry key, and scheduled task manually removed.
* **Telemetry Expansion:** Queries extended to check lateral movement beyond `anthony-001`.
* **Awareness:** Flag shared with Blue Team and Detection Engineering for rule creation.

---

## Lessons Learned

* Malware impersonating legitimate tools can easily evade static detection without behavioral telemetry.
* Scheduled tasks with realistic names (e.g. `UpdateHealthTelemetry`) can persist undetected.
* LOLBins like `csc.exe` can be abused post-download to deploy compiled malware.
* Registry and Startup folders remain top persistence targets.

---

**Report Completed By:** Tracey Buentello
**Status:** ✅ All 8 flags investigated and confirmed
