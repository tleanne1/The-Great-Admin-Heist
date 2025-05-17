# Threat Event (The Great Admin Heist)

**Unauthorized Malware Deployment via Fake Antivirus and Stealth Persistence**

## Steps the "Bad Actor" took to Create Logs and IoCs:

1. Phished the administrator (Bubba Rockerfeatherman III) and delivered a disguised payload `BitSentinelCore.exe`
2. Compiled the fake AV using native Windows utility `csc.exe` and dropped it into `C:\ProgramData\`
3. Bubba unknowingly executed the malware manually
4. The malware:

   * Dropped a `.lnk` shortcut named `systemreport.lnk` to log keystrokes
   * Created a registry key to ensure persistence: `HKCU\...\Run`
   * Created a scheduled task named `UpdateHealthTelemetry` to run daily
5. Process chain observed:

   * `BitSentinelCore.exe -> cmd.exe -> schtasks.exe`
6. Registry modification confirmed persistence on reboots
7. Scheduled task guaranteed malware reinfection during login

---

## Tables Used to Detect IoCs:

| **Parameter** | **Description**                                                                                                                                                                  |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceFileEvents                                                                                                                                                                 |
| **Info**      | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose**   | Identified the malware drop, creation of `systemreport.lnk`, and folder paths used by the attacker                                                                               |

| **Parameter** | **Description**                                                                                                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceProcessEvents                                                                                                                                                                    |
| **Info**      | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose**   | Tracked execution flow of BitSentinelCore.exe and subsequent process chain leading to persistence setup                                                                                |

| **Parameter** | **Description**                                                                                                                                                                          |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceRegistryEvents                                                                                                                                                                     |
| **Info**      | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table) |
| **Purpose**   | Detected registry key `BitSecSvc` created to auto-run `BitSentinelCore.exe` under `HKCU\...\Run`                                                                                         |

---

## Related Queries:

```kql
// Malware dropped to disk
DeviceFileEvents
| where FileName == "BitSentinelCore.exe"

// Manual execution of the malware by Bubba
DeviceProcessEvents
| where FileName == "BitSentinelCore.exe"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName

// Keylogger shortcut dropped
DeviceFileEvents
| where FileName == "systemreport.lnk"

// Registry key persistence
DeviceRegistryEvents
| where RegistryKey contains "Run"
| where RegistryValueData has "BitSentinelCore"

// Scheduled task creation
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "UpdateHealthTelemetry"

// Full process chain
DeviceProcessEvents
| where InitiatingProcessFileName == "BitSentinelCore.exe"
| project Timestamp, FileName, InitiatingProcessFileName
```

---

## Created By:

* **Author Name**: Tracey B
* **Author Contact**: [https://www.linkedin.com/in/tleanne/](https://www.linkedin.com/in/tleanne/)
* **Date**: May 2025

## Validated By:

* **Reviewer Name**:
* **Reviewer Contact**:
* **Validation Date**:

---

## Additional Notes:

* This simulation was part of the "CTF: The Great Admin Heist" challenge, focused on endpoint detection, KQL analysis, and persistence detection across registry and scheduled tasks.

---

## Revision History:

| **Version** | **Changes**   | **Date**   | **Modified By** |
| ----------- | ------------- | ---------- | --------------- |
| 1.0         | Initial draft | `May 2025` | `Tracey B`      |
