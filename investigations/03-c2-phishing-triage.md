# Investigation 03 — C2 Beaconing / Phishing Triage
**Dataset:** Splunk Boss of the SOC (BOTS) v1  
**Date:** April 2026  
**Analyst:** Shyam Srujan  
**Status:** Complete — Escalated to Tier 2

---

## Alert details (raw)

**Source:** Splunk — DNS logs + proxy logs  
**Alert name:** Suspicious DNS beaconing pattern — consistent interval, low TTL  

| Field | Value |
|---|---|
| Source host | `we8105desk` |
| Queried domain | `hildegardtrosper.com` |
| Query frequency | Every 60 seconds ± 3 seconds |
| Query type | A record |
| DNS TTL | 60 seconds |
| First seen | 2016-08-10 21:32:11 UTC |
| Last seen | 2016-08-10 22:14:58 UTC |
| Resolved IPs | `160.16.218.202` (rotated 3x) |

**SPL query used:**
```spl
index=botsv1 host=we8105desk sourcetype=stream:dns
| timechart span=1m count by query
| where like(query, "%hildegardtrosper%")
```

---

## AI prompt used

```
You are a SOC analyst assistant helping with Tier 1 triage.

Alert details:
- Host: we8105desk
- Behavior: DNS queries to hildegardtrosper.com every 60 seconds ± 3 seconds
- Query type: A record, TTL 60 seconds (very low)
- Duration: 42 minutes of consistent beaconing
- Resolved to 3 different IPs over that window (fast flux pattern)
- Timestamp: 2016-08-10 21:32 UTC

Provide:
1. Is this behavior suspicious? Why or why not?
2. MITRE ATT&CK technique ID and name this most likely maps to
3. Severity: Low / Medium / High / Critical — with reasoning
4. Next 3 log sources or pivots I should investigate
5. Draft a one-paragraph Tier 1 triage note in plain English
Do not assume malicious intent without clear indicators. Flag uncertainty.
```

---

## AI output (summarized)

**Suspicious?** Yes — very high confidence. Three indicators combine here: (1) highly consistent beacon interval (60s ± 3s is machine-generated, not human), (2) 60-second TTL is a classic C2 infrastructure technique to enable fast IP rotation, (3) fast flux DNS (3 IPs in 42 minutes) is specifically designed to evade IP-based blocklists.

**MITRE ATT&CK mapping:**
- `T1071.004` — Application Layer Protocol: DNS (C2 over DNS)
- `T1568.001` — Dynamic Resolution: Fast Flux DNS
- `T1071.001` — Application Layer Protocol: Web Protocols (if HTTP C2 follows)

**Severity:** Critical

**Recommended pivots:**
1. Check proxy/HTTP logs from `we8105desk` for outbound connections to the resolved IPs — DNS beaconing is usually followed by HTTP C2 channel
2. Check what process on `we8105desk` is making the DNS calls (Sysmon Event ID 22 — DNS query with process name)
3. Correlate timing — does this beaconing start immediately after the ransomware event? (This is the same host from Investigation 01)

**AI-drafted triage note:**
> Host `we8105desk` is sending DNS queries to `hildegardtrosper.com` at consistent 60-second intervals over a 42-minute window. The regularity, low TTL, and fast-flux resolution pattern are consistent with C2 beaconing. This activity maps to MITRE T1071.004 and T1568.001. The host should be considered actively compromised and communicating with attacker infrastructure.

---

## My independent analysis

**Process identification (Sysmon DNS):**
```spl
index=botsv1 host=we8105desk sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=22
| where like(QueryName, "%hildegardtrosper%")
| table _time, ProcessGuid, QueryName, User
```
Result: Process GUID traced back to `wscript.exe` — same process from the ransomware event. This is the same infection, same malware, same session.

**HTTP C2 confirmation:**
```spl
index=botsv1 host=we8105desk sourcetype=stream:http dest_ip=160.16.218.202
| table _time, src_ip, dest_ip, uri, http_method, status
```
Result: HTTP POST requests to `/gate.php` at `160.16.218.202` — classic Ryuk C2 check-in endpoint pattern. Data exfiltration cannot be ruled out.

**Correlation with Investigation 01:**
This beaconing began at `21:32 UTC` — 14 minutes before the ransomware encryption began at `21:46 UTC`. This is the C2 check-in phase that precedes Ryuk deployment. The attacker was staging before detonating.

**What AI got right:** Identified all three C2 indicators correctly. The pivot to Sysmon Event ID 22 was exactly right — that's what confirmed the process. The fast flux analysis was precise.

**What I added:** Correlated this with Investigation 01 to establish the attack timeline. This is not two separate incidents — it's a single Ryuk ransomware infection with a distinct C2 phase preceding encryption. That changes the scope significantly for Tier 2.

---

## Disposition

**True Positive — Critical. Escalated to Tier 2.**

Active C2 communication confirmed. Same host as ransomware event. Attack timeline now established: C2 beaconing (21:32) → ransomware detonation (21:46). Possible staging/data exfiltration in the 14-minute window.

**Actions taken:**
1. Immediately escalated to Tier 2 with full correlated timeline
2. Linked to Investigation 01 ticket as related incident
3. Flagged potential data exfiltration window for forensic review

---

## Final incident ticket

**Summary:** C2 beaconing from `we8105desk` to known Ryuk infrastructure confirmed. Activity began 14 minutes before ransomware detonation, establishing the full attack timeline. Same process (`wscript.exe`) responsible for both C2 and encryption. Possible data staging/exfiltration in 14-minute pre-detonation window.

**Timeline:**
- `21:31 UTC` — `bob.smith` authenticates (possibly phishing-delivered credential)
- `21:32 UTC` — C2 beaconing begins to `hildegardtrosper.com`
- `21:32–21:46 UTC` — HTTP POST check-ins to `/gate.php` (staging phase)
- `21:45 UTC` — VSS deletion command executed
- `21:46 UTC` — Ransomware encryption begins
- `22:14 UTC` — Last observed beacon

**Affected assets:** `we8105desk` · `bob.smith` · Ryuk C2: `hildegardtrosper.com` / `160.16.218.202`

**IOCs:**
- C2 domain: `hildegardtrosper.com`
- C2 IPs: `160.16.218.202` (fast flux, 3 IPs total)
- C2 URI: `/gate.php`
- Process: `wscript.exe` (PID from Sysmon log)
- Beacon interval: 60 seconds ± 3 seconds

**MITRE ATT&CK:** T1071.004 · T1568.001 · T1486 · T1490

**Analyst disposition:** True Positive — Critical. Escalated. Related to INC-001 (Investigation 01).

**Reasoning:** Three independent indicators confirm C2 (beacon regularity, fast flux, HTTP check-in to known endpoint). Timeline correlation establishes this is the staging phase of the ransomware attack documented in INC-001.

**Recommended Tier 2 next steps:**
- Forensic image of `we8105desk` before further changes
- Review HTTP POST payloads for data exfiltration content
- Investigate how `bob.smith` credentials were compromised (phishing likely)
- Threat hunt for same C2 domain/IPs across all other hosts
- Block `hildegardtrosper.com` and associated IPs at DNS/firewall level

---

## Key takeaway

This investigation shows where AI-augmented triage goes beyond just closing tickets. The AI's pivot recommendation to check Sysmon Event ID 22 is what let me identify the process and connect this to Investigation 01. Without that, these would have been two separate tickets. With it, Tier 2 gets a complete attack narrative — C2 staging through encryption — in a single escalation. That's the difference between a Tier 1 analyst who processes alerts and one who understands attacks.
