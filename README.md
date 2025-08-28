# Network Slowdown (Potential Port Scan)


##  Summary
During routine monitoring, I detected unusual failed connection attempts originating from device **kel-99**. The host was repeatedly attempting to connect to its own address and another peer, with failures occurring across multiple ports in sequence. This behavior was consistent with an **internal port scan**.

---

##  Investigation Steps

### 1. Detecting Failed Connections
```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by ConnectionCount
```
<img width="975" height="160" alt="image" src="https://github.com/user-attachments/assets/85cbbb59-9cf1-4ad8-93cf-f8df55d7fa7b" />

---

<img width="791" height="357" alt="image" src="https://github.com/user-attachments/assets/8df14db1-09a5-4c85-b1e3-377cd40922f5" />


- Numerous failed connection attempts were identified from **10.0.0.78**.  
- Remote port numbers advanced sequentially across well-known service ports (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 443, etc.).  
- Pattern indicated **active port scanning activity**.

---

### 2. Pivot to Process Events
```kql
let VMName = "kel-99";
let specificTime = datetime(2025-08-27T18:17:05.0401901Z);

DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName, SHA256
```
<img width="975" height="79" alt="image" src="https://github.com/user-attachments/assets/a727ff00-df91-4c49-824c-278f320101b7" />

---

<img width="923" height="343" alt="image" src="https://github.com/user-attachments/assets/f7024466-7611-4c34-8ccc-021084290d6c" />


- Identified **PowerShell launching `portscan.ps1`**.  
- Command line: `cmd.exe /c powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\portscan.ps1`  
- Executed under account **kelzteck**.
- **PowerShell script** responsible for the port scan.
  
---

### 3. Containment & Response
- Isolated device in **Microsoft Defender for Endpoint**.  
- Triggered **full malware scan** with cloud-delivered protection.  
- Exported process & network event logs, script file, and hash values.  
- Captured active user session for evidence.  
- Escalated by opening a **reimage/rebuild ticket** and notifying the incident lead.

---

##  MITRE ATT&CK Mapping

| Technique ID | Tactic / Technique | Evidence |
|--------------|--------------------|----------|
| **T1046** | **Network Service Discovery (Discovery)** | Sequential failed connections across many well-known ports |
| **T1059.001** | **Command & Scripting Interpreter: PowerShell (Execution)** | Execution of `portscan.ps1` via PowerShell |
| **T1059.003** | **Command & Scripting Interpreter: Windows Command Shell (Execution)** | `cmd.exe` launching PowerShell |

---

##  Lessons Learned
- **Early detection of failed connections** across sequential ports is a strong indicator of scanning activity.  
- **Pivoting from network logs to process events** helped quickly identify the malicious script and user context.  
- Immediate isolation reduced potential lateral movement and service disruption.  

---

##  Skills Demonstrated
- Threat Hunting with Microsoft Defender for Endpoint  
- Advanced KQL Querying  
- MITRE ATT&CK Framework Mapping  
- Incident Containment & Response  
