# Investigation 01 — Ransomware Triage
**Dataset:** Splunk Boss of the SOC (BOTS) v1  
**Date:** April 2026  
**Analyst:** Shyam Srujan  
**Status:** Complete

---

## Alert details (raw)

**Source:** Splunk — Windows Event Log + Sysmon  
**Alert name:** Suspicious process spawning — mass file rename activity  

| Field | Value |
|---|---|
| Hostname | `we8105desk` |
| User | `bob.smith` |
| Parent process | `explorer.exe` |
| Child process | `cmd.exe` → `wscript.exe` |
| Command line | `wscript.exe //B //Nologo %TEMP%\vssadmin.vbs` |
| Volume Shadow Copy | `vssadmin.exe delete shadows /all /quiet` |
| File rename events | 5,000+ files renamed to `.ryk` extension in 4 minutes |
| Timestamp | 2016-08-10 21:46:17 UTC |

**SPL query used to surface this:**
```spl
index=botsv1 sourcetype=xmlwineventlog EventCode=4688
| where like(CommandLine, "%vssadmin%")
| table _time, host, user, ParentProcessName, CommandLine
```

---

## AI prompt used

```
You are a SOC analyst assistant helping with Tier 1 triage.

Alert details:
- Event ID: 4688
- Parent process: explorer.exe → cmd.exe
- Child process: wscript.exe
- Command line: wscript.exe //B //Nologo %TEMP%\vssadmin.vbs
- Secondary command: vssadmin.exe delete shadows /all /quiet
- User: bob.smith
- Hostname: we8105desk
- Observed: 5000+ files renamed to .ryk extension over 4 minutes
- Timestamp: 2016-08-10 21:46:17 UTC

Provide:
1. Is this behavior suspicious? Why or why not?
2. MITRE ATT&CK technique ID and name this most likely maps to
3. Severity: Low / Medium / High — with reasoning
4. Next 3 log sources or pivots I should investigate
5. Draft a one-paragraph Tier 1 triage note in plain English
```

---

## AI output (summarized)

**Suspicious?** Yes — high confidence. `vssadmin delete shadows` is a canonical ransomware pre-encryption step. Combined with mass file renaming to a consistent extension (`.ryk`), this is textbook ransomware execution.

**MITRE ATT&CK mapping:**
- `T1486` — Data Encrypted for Impact (primary)
- `T1490` — Inhibit System Recovery (VSS deletion)
- `T1059.005` — Command and Scripting Interpreter: Visual Basic

**Severity:** Critical

**Recommended pivots:**
1. Check network logs for outbound C2 connections from `we8105desk` in the 30 minutes before encryption began
2. Check Sysmon Event ID 11 (FileCreate) for the `.ryk` file write pattern across the disk
3. Check authentication logs — was `bob.smith` the actual user or was this a compromised account?

**AI-drafted triage note:**
> Host `we8105desk` under user account `bob.smith` executed a script that deleted all Volume Shadow Copies and subsequently renamed over 5,000 files with a `.ryk` extension consistent with Ryuk ransomware. The VSS deletion prevents recovery via Windows backup. This pattern matches MITRE T1486 and T1490. Immediate isolation recommended pending Tier 2 review.

---

## My independent analysis

**Verified in Splunk:**

```spl
index=botsv1 host=we8105desk sourcetype=xmlwineventlog EventCode=4663
| stats count by Object_Name
| where like(Object_Name, "%.ryk")
| sort -count
```
Result: 5,147 file rename events confirmed. Files across `C:\Users\bob.smith\Documents` and mapped network shares.

**Network pivot:**
```spl
index=botsv1 host=we8105desk sourcetype=stream:dns
| table _time, query
| sort _time
```
Result: DNS queries to `hildegardtrosper.com` — flagged in threat intel as Ryuk C2 domain (VirusTotal: 47/73 engines malicious).

**Authentication check:**
`bob.smith` had a successful login at 21:31 UTC — 15 minutes before execution began. No anomalous login source. Likely compromised credentials or phishing-delivered dropper.

**What AI got right:** MITRE mapping, severity call, VSS significance, pivot recommendations — all correct and saved me approximately 8 minutes of initial context-building.

**What I added:** Confirmed C2 domain via DNS log pivot. Identified the specific ransomware family (Ryuk) from the `.ryk` extension and C2 domain. Determined the likely infection vector was pre-existing — not a live intrusion in progress.

---

## Disposition

**True Positive — Critical**

Active Ryuk ransomware encryption event. VSS deleted. Network shares affected. C2 communication confirmed.

**Immediate actions taken:**
1. Flagged for immediate host isolation
2. Escalated to Tier 2 with full ticket
3. Noted network share impact for business continuity assessment

---

## Final incident ticket

**Summary:** Active Ryuk ransomware execution confirmed on `we8105desk` under account `bob.smith`. Volume Shadow Copies deleted, 5,147+ files encrypted, C2 communication to known Ryuk infrastructure detected.

**Timeline:**
- `21:31 UTC` — `bob.smith` authenticates successfully
- `21:44 UTC` — `wscript.exe` executes VBS dropper from `%TEMP%`
- `21:45 UTC` — `vssadmin delete shadows /all /quiet` executed
- `21:46 UTC` — Mass file encryption begins (`.ryk` extension)
- `21:50 UTC` — Alert triggered by file rename volume threshold
- `21:58 UTC` — Analyst triage complete, escalation submitted

**Affected assets:** `we8105desk` · `bob.smith` · mapped network shares (scope TBD by Tier 2)

**IOCs:**
- File extension: `.ryk`
- Domain: `hildegardtrosper.com`
- Process chain: `explorer.exe → cmd.exe → wscript.exe → vssadmin.exe`
- Script: `%TEMP%\vssadmin.vbs`

**MITRE ATT&CK:** T1486 · T1490 · T1059.005

**Analyst disposition:** True Positive — Critical. Escalated.

**Reasoning:** VSS deletion + mass file renaming to known ransomware extension + confirmed C2 DNS traffic leaves no ambiguity. No false positive indicators present.

**Recommended Tier 2 next steps:**
- Isolate `we8105desk` immediately
- Identify initial infection vector (check email logs around 21:00–21:31)
- Audit network share access logs for lateral spread
- Preserve forensic image before remediation

---

## Key takeaway

AI gave me the MITRE mapping and pivot recommendations in under 30 seconds. I used that head start to run the right Splunk queries and confirm the C2 domain — the part that turned this from a suspicion into a confirmed incident. Total triage time: **~4 minutes** vs estimated 12–15 minutes without AI assist.
