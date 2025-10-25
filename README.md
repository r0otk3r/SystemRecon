# 🖥️ Full Computer Enumeration Toolkit

**Comprehensive system, security, network, and forensic data collection for Windows systems.**  
Ideal for security analysts, incident responders, and forensic investigators who need to extract complete system intelligence efficiently.

---

## 📘 Overview

The **Full Computer Enumeration Toolkit** is a PowerShell-based auditing and collection framework that gathers extensive details about a Windows machine  including hardware, processes, users, event logs, registry data, security settings, and forensic artifacts.

It automatically generates organized reports into categorized folders for easy analysis and evidence preservation.

---

## ⚙️ Features

✅ **System & Hardware Inventory**
- OS, BIOS, CPU, RAM, Disk, and Device details  
- Network adapters, GPUs, USB devices, and printers

✅ **Network & Security**
- IP configuration, open/listening ports, firewall rules  
- DNS cache, ARP table, and network shares

✅ **User & Group Enumeration**
- Local users, groups, privileges, sessions, and user profiles

✅ **Processes & Services**
- Running processes, service details, dependencies, and startup paths

✅ **Event Log Analysis**
- Collects key logs from System, Application, Security, and PowerShell  
- Extracts critical security events (logon, service install, privilege escalation)

✅ **Registry & Filesystem**
- Auto-start locations, installed software, startup items  
- Suspicious executables and file hash generation (SHA256)

✅ **Security Configuration**
- Defender status, UAC policy, BitLocker state, and audit policy

✅ **Forensic Support**
- Optional memory dump, quick mode, and network capture

---

## 🚀 Usage

Run the script in **PowerShell 5.1 or later**. For full functionality **run as Administrator**.

---

### 🧩 Temporary Script Execution (Recommended - Safer)

This allows the script to run only in the current PowerShell session (no permanent change):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Full_Computer_Enumeration.ps1
```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
➤ Temporarily allows script execution for the current session.

.\Full_Computer_Enumeration.ps1
➤ Runs the toolkit.
### ⚠️ Permanently Allow Script Execution (Higher Risk)
If you trust your scripts and want to allow execution persistently:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
- RemoteSigned allows locally created scripts to run, and requires remote scripts to be signed.

- This setting persists across sessions and applies to the current user.

### 🔍 Check Current Execution Policy

To view current execution policies for all scopes:
```powershell
Get-ExecutionPolicy -List
```
#### Example Output:
```mathematica
        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
UserPolicy          Undefined
Process             Bypass
CurrentUser         RemoteSigned
LocalMachine        Restricted
```
## 🧠 Example Full Run
```powershell
# Temporary bypass for this session (recommended)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Full_Computer_Enumeration.ps1

# OR — permanently allow signed/local scripts
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# Verify execution policy
Get-ExecutionPolicy -List
```
### 🧩 Script Parameters
| Parameter           | Type   | Default                              | Description                                           |
| ------------------- | ------ | ------------------------------------ | ----------------------------------------------------- |
| `OutputPath`        | String | `.\Computer_Enumeration_<TIMESTAMP>` | Path where output data will be stored                 |
| `QuickMode`         | Switch | `False`                              | Runs essential modules only (faster)                  |
| `IncludeMemoryDump` | Switch | `False`                              | Captures full system memory dump                      |
| `NetworkCapture`    | Switch | `False`                              | Captures live network traffic (requires admin rights) |
| `EventLogDays`      | Int    | `30`                                 | Number of days of event logs to collect               |
| `SkipHashes`        | Switch | `False`                              | Skip file hashing during collection                   |

---
## 📂 Output Structure

The toolkit generates a structured directory under the chosen output path, such as:
```matlab
Computer_Enumeration_20251025_143512\
├── System_Info\
├── Network\
├── Processes\
├── Services\
├── Users_Groups\
├── Event_Logs\
├── Registry\
├── Filesystem\
├── Security\
├── Forensic\
├── Memory\
└── enumeration.log
```
Each folder contains .csv and .txt exports of the collected data, suitable for Excel, Splunk, or forensic review.

---

## 🧠 Notes & Security Considerations

- Must be run as Administrator to access all system and security data.

- The toolkit is read-only  it collects data and does not modify or delete files.

- Changing execution policies can increase system risk:

- Use -Scope Process for one-time execution (recommended).

- Avoid weakening LocalMachine policies unless absolutely necessary.

- Redact sensitive data before sharing results (e.g., usernames, hashes, IPs).

## 📄 License & Credits

Created: © 2025

License: Internal / Research Use Only

## 🧰 Recommended Usage Scenarios

🧑‍💻 SOC / DFIR environments for full machine triage

🕵️ Security audits or penetration test data collection

🧾 Post-compromise analysis and evidence preservation

⚙️ Routine health checks and system configuration review

---

## 🧩 Quick Reference Commands

| Task                          | PowerShell Command                                                     |
| ----------------------------- | ---------------------------------------------------------------------- |
| **Run temporarily (safe)**    | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`           |
| **Run the script**            | `.\Full_Computer_Enumeration.ps1`                                      |
| **Allow scripts permanently** | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` |
| **Check execution policies**  | `Get-ExecutionPolicy -List`                                            |

---

## Official Channels

- [Telegram @r0otk3r](https://t.me/r0otk3r)
- [X @r0otk3r](https://x.com/r0otk3r)
