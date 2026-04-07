# Investigation 01 — Ransomware Triage (VSS Deletion)
**Dataset:** Splunk Boss of the SOC (BOTS) v1  
**Analyst:** Shyam Srujan  
**Status:** Complete — True Positive

---

## Alert details (raw)

**Source:** Splunk — Windows Security Event Log (`WinEventLog:Security`)  
**Alert trigger:** Suspicious process creation — Volume Shadow Copy deletion

| Field | Value |
|---|---|
| Host | `we8105desk` |
| Domain | `WAYNECORPINC` |
| User | `bob.smith` |
| Event ID | `4688` (Process Creation) |
| New process | `C:\Windows\System32\vssadmin.exe` |
| Command line | `C:\Windows\system32\vssadmin.exe delete shadows /all /quiet` |
| Timestamp | `2016-08-24T12:49:23-04:00` |
| Keywords | `Audit Success` |

---

## SPL query used

```spl
index=botsv1 host=we8105desk sourcetype=WinEventLog:Security EventCode=4688
| search Process_Command_Line="*vssadmin*"
| table _time, host, Account_Name, New_Process_Name, Process_Command_Line
```

**Result:** 1 event returned.

---

## AI prompt used

```
You are a SOC analyst assistant helping with Tier 1 triage.

Alert details:
- Event ID: 4688 (Process Creation)
- Host: we8105desk
- Domain: WAYNECORPINC
- User: bob.smith
- New process: C:\Windows\System32\vssadmin.exe
- Command line: vssadmin.exe delete shadows /all /quiet
- Timestamp: 2016-08-24T12:49:23

Provide:
1. Is this behavior suspicious? Why or why not?
2. MITRE ATT&CK technique ID and name
3. Severity: Low / Medium / High / Critical
4. Next 3 pivots to investigate
5. Draft a Tier 1 triage note
```

---

## AI output (summary)

**Suspicious?** Yes — critical confidence. `vssadmin delete shadows /all /quiet` is the most commonly observed pre-encryption command in ransomware attacks. Deleting Volume Shadow Copies removes the victim's ability to restore files via Windows backup.

**MITRE ATT&CK:**
- `T1490` — Inhibit System Recovery (primary)
- `T1059.003` — Command and Scripting Interpreter: Windows Command Shell

**Severity:** Critical

**Recommended pivots:**
1. Check for mass file rename/create events on `we8105desk` after this timestamp
2. Check network connections from `we8105desk` to external IPs around the same time
3. Check authentication logs — was `bob.smith` the legitimate user or a compromised account?

---

## My independent analysis

**Verified the command in Splunk:**

The `Process_Command_Line` field confirmed:
```
C:\Windows\system32\vssadmin.exe delete shadows /all /quiet
```

`/all` — deletes all shadow copies on all volumes  
`/quiet` — suppresses confirmation prompts — silent execution, attacker-controlled

**Account context:**
- `Account_Name`: `bob.smith`
- `Account_Domain`: `WAYNECORPINC`
- `Token_Elevation_Type`: `TokenElevationTypeFull` — process ran with full admin privileges

Full elevation on a standard user account running vssadmin is a strong indicator of privilege escalation preceding this command.

**What AI got right:** MITRE mapping, severity, and the pivot to check network connections — all correct. The T1490 mapping is exact.

**What I added:** Identified the elevation type as `TokenElevationTypeFull` — this means the attacker had already escalated privileges before running this command. That changes the scope from "suspicious process" to "active attacker with admin access."

---

## Disposition

**True Positive — Critical**

Confirmed ransomware pre-encryption activity. Volume Shadow Copies deleted with admin privileges on `we8105desk` under account `bob.smith`.

---

## Incident ticket

**Summary:** `vssadmin delete shadows /all /quiet` executed on `we8105desk` under `bob.smith` with full token elevation. Classic ransomware VSS deletion — confirms active attacker with admin access. Correlated with suspicious HTTP staging traffic (see Investigation 02).

**Timeline:**
- `2016-08-10` — Malware staging HTTP traffic observed (Investigation 02)
- `2016-08-24 12:49:23` — VSS deletion executed on `we8105desk`

**Affected assets:** `we8105desk.waynecorpinc.local` · `bob.smith`

**IOCs:**
- Command: `vssadmin.exe delete shadows /all /quiet`
- Process path: `C:\Windows\System32\vssadmin.exe`
- Event ID: `4688`
- Elevation: `TokenElevationTypeFull`

**MITRE ATT&CK:** T1490 · T1059.003

**Disposition:** True Positive — Critical. Escalate immediately.

**Tier 2 next steps:**
- Determine full scope of encrypted files
- Identify initial access vector for `bob.smith` compromise
- Correlate with HTTP staging traffic from Investigation 02
- Preserve forensic image before remediation
