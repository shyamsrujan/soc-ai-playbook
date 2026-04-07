# SOC AI Playbook — Investigation Report
**Analyst:** Shyam Srujan  
**Dataset:** Splunk Boss of the SOC (BOTS) v1  
**Tools:** Splunk Enterprise · Claude (LLM) · MITRE ATT&CK  
**Classification:** Public

---

## Executive Summary

This report documents two Tier 1 SOC investigations conducted against the Splunk Boss of the SOC (BOTS) v1 dataset — a publicly available attack simulation used globally for security analyst training.

Both investigations used an **AI-augmented triage workflow**: raw alert data was fed into a structured LLM prompt to accelerate MITRE technique mapping, severity assessment, and pivot identification. All dispositions were made independently by the analyst.

**Two true positives confirmed:**

| # | Finding | MITRE | Severity | Disposition |
|---|---|---|---|---|
| 01 | Ransomware VSS deletion on `we8105desk` | T1490, T1059.003 | Critical | True Positive — Escalated |
| 02 | Malware staging via Microsoft CDN abuse | T1102.002, T1036, T1041 | High (P2) | True Positive — Escalated |

These two findings are correlated — Investigation 02 (staging) preceded Investigation 01 (ransomware detonation) by 14 days, indicating a single attacker campaign with a dwell time of at least two weeks.

---

## Attack Timeline

```
2016-08-10 17:55 UTC  ←── Malware staging begins
                           192.168.250.100 → 13.107.4.50
                           35 HTTP connections, OneDrive C2 pattern
                           URI masquerading as Windows Update
                           [Investigation 02]

        ← 14 days dwell time →

2016-08-24 12:49 UTC  ←── Ransomware pre-encryption
                           we8105desk\bob.smith
                           vssadmin.exe delete shadows /all /quiet
                           TokenElevationTypeFull — admin access confirmed
                           [Investigation 01]
```

**Key observation:** The 14-day gap between staging and detonation is consistent with human-operated ransomware campaigns. The attacker established access, staged tools via cloud infrastructure, and detonated at a chosen time — not an automated worm.

---

## Investigation 01 — Ransomware VSS Deletion

### What was found

A single `EventCode=4688` (process creation) event on host `we8105desk` showing:

```
Process: C:\Windows\System32\vssadmin.exe
Command: vssadmin.exe delete shadows /all /quiet
User: bob.smith (WAYNECORPINC domain)
Elevation: TokenElevationTypeFull
Timestamp: 2016-08-24T12:49:23
```

### Why it matters

`vssadmin delete shadows /all /quiet` removes all Windows Volume Shadow Copies — the built-in backup mechanism. This is executed immediately before ransomware begins encrypting files to prevent recovery. It is one of the most reliable indicators of active ransomware.

The `TokenElevationTypeFull` value confirms the attacker had already escalated to full administrator privileges before running this command.

### AI contribution

The LLM correctly mapped this to `T1490` (Inhibit System Recovery) and recommended checking network connections from the host around the same timestamp — which led to the correlation with Investigation 02.

**SPL query that found it:**
```spl
index=botsv1 host=we8105desk sourcetype=WinEventLog:Security EventCode=4688
| search Process_Command_Line="*vssadmin*"
| table _time, host, Account_Name, New_Process_Name, Process_Command_Line
```

---

## Investigation 02 — Malware Staging via Legitimate Cloud Infrastructure

### What was found

35 HTTP connections from an internal host to `13.107.4.50` (Microsoft CDN / OneDrive infrastructure) over a 19-minute window:

```
Source:      192.168.250.100 (internal host)
Destination: 13.107.4.50 (Microsoft CDN)
Count:       35 connections over 19 minutes
URI pattern: /filestreamingservice/files/{GUID}/pieceshash
Masquerade:  /c/msdownload/update/software/secu/windows10.0-{hash}.cab
Timeframe:   2016-08-10 17:55 – 18:14 UTC
```

### Why it matters

**Living-off-trusted-sites (LOTS)** is an advanced evasion technique. Attackers use legitimate cloud platforms — OneDrive, Dropbox, Google Drive — as C2 channels because:
- Most firewalls and proxies whitelist these domains/IPs
- Traffic blends with normal business activity
- Forensic attribution is harder

The masquerading URI (`/c/msdownload/update/software/secu/`) is crafted to look like a legitimate Windows update download. Real Windows Update traffic goes through `windowsupdate.microsoft.com` via WSUS — not this path pattern. This is a deliberate deception artifact.

### AI contribution

The LLM immediately identified `T1102.002` (Web Service C2) as the primary technique and flagged the masquerading URI as a red flag — explaining specifically why the path doesn't match legitimate WSUS behavior. This analysis would have taken 10-15 minutes of manual research to reach independently.

**SPL query that found it:**
```spl
index=botsv1 sourcetype=stream:http dest_ip=13.107.4.50
| table _time, src_ip, dest_ip, uri, status, bytes_out
| sort _time
```

---

## AI-Augmented Workflow — How It Was Used

### The workflow

```
1. Splunk alert / query result
         ↓
2. Structured AI prompt (from prompt library)
         ↓
3. AI output: MITRE mapping · severity · pivot recommendations
         ↓
4. Independent verification in Splunk
         ↓
5. Analyst disposition (TP / FP / Escalate)
         ↓
6. Structured incident ticket
```

### What AI accelerated

| Task | Without AI | With AI |
|---|---|---|
| MITRE technique mapping | 8-10 min research | ~15 seconds |
| Severity framing | Analyst judgment | Structured starting point |
| Next pivot identification | Experience-dependent | Consistent recommendations |
| Ticket drafting | 5-10 min writing | Template populated in seconds |

### What AI cannot do

- Make the disposition call (TP/FP/Escalate) — that requires analyst judgment
- Access the actual SIEM data — all queries were run independently
- Know organizational context (asset criticality, business hours, authorized tools)
- Be held accountable — a human analyst owns every decision

**The analyst is not a rubber stamp.** In Investigation 02, the AI identified the correct technique but the analyst added the specific insight about the 14-day dwell time correlation — connecting two separate alerts into a single campaign narrative.

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Investigation |
|---|---|---|
| T1490 | Inhibit System Recovery | 01 |
| T1059.003 | Windows Command Shell | 01 |
| T1102.002 | Web Service — Bidirectional Communication | 02 |
| T1036 | Masquerading | 02 |
| T1041 | Exfiltration Over C2 Channel | 02 |

---

## Prompt Library

Six structured prompts used in these investigations are documented in [`prompt-library/tier1-prompts.md`](../prompt-library/tier1-prompts.md).

Each prompt is designed to extract specific, actionable output — not generic summaries. The prompts cover:
- Suspicious process / LOLBins triage
- Obfuscated PowerShell decoding
- Phishing email header analysis
- IOC enrichment
- MITRE technique lookup
- Incident ticket generation

---

## About This Project

This playbook was built to demonstrate AI-augmented Tier 1 SOC triage using real public attack data. All findings are based on the **Splunk BOTS v1 dataset** — a publicly available, fictional attack simulation. No real organizational data was used.

**Author:** Shyam Srujan  
M.S. Computer Science — Illinois Institute of Technology  
Former App Engineering Associate — Accenture  
Volunteer Cybersecurity Analyst — CDF  

[GitHub](https://github.com/shyamsrujan) · [LinkedIn](https://linkedin.com/in/shyamsrujan) · [Portfolio](https://portfolio-rose-ten-95.vercel.app)

---

*Dataset: Splunk Boss of the SOC v1 — public dataset, no proprietary or personal data.*  
*All hostnames, usernames, and IP addresses are from the fictional WAYNECORPINC simulation environment.*
