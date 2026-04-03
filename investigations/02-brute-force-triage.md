# Investigation 02 — Brute Force / Credential Stuffing Triage
**Dataset:** Splunk Boss of the SOC (BOTS) v1  
**Date:** April 2026  
**Analyst:** Shyam Srujan  
**Status:** Complete

---

## Alert details (raw)

**Source:** Splunk — Windows Security Event Log  
**Alert name:** High-volume authentication failures — single source IP  

| Field | Value |
|---|---|
| Source IP | `23.22.63.114` |
| Target host | `imreallynotbatman.com` (web server) |
| Event type | HTTP 401 Unauthorized |
| Attempt count | 1,814 POST requests to `/joomla/administrator/index.php` |
| Timeframe | 6 minutes (14:00–14:06 UTC) |
| User agents | Mixed — automated tooling pattern |
| Timestamp | 2016-08-10 14:00:22 UTC |

**SPL query used:**
```spl
index=botsv1 sourcetype=stream:http http_method=POST uri="/joomla/administrator/index.php"
| stats count by src_ip, status
| sort -count
```

---

## AI prompt used

```
You are a SOC analyst assistant helping with Tier 1 triage.

Alert details:
- Alert type: High-volume authentication failures
- Source IP: 23.22.63.114
- Target: imreallynotbatman.com — /joomla/administrator/index.php
- Event: 1,814 POST requests in 6 minutes, all returning HTTP 401
- User agents: inconsistent, mixed strings suggesting automation
- Timestamp: 2016-08-10 14:00:22 UTC

Provide:
1. Is this behavior suspicious? Why or why not?
2. MITRE ATT&CK technique ID and name this most likely maps to
3. Severity: Low / Medium / High — with reasoning
4. Next 3 log sources or pivots I should investigate
5. Draft a one-paragraph Tier 1 triage note in plain English
```

---

## AI output (summarized)

**Suspicious?** Yes — definitively. 1,814 authentication attempts in 6 minutes from a single IP against an admin panel is automated brute force, not human behavior.

**MITRE ATT&CK mapping:**
- `T1110.001` — Brute Force: Password Guessing
- `T1190` — Exploit Public-Facing Application (if a successful login follows)

**Severity:** High (escalates to Critical if any attempt succeeds)

**Recommended pivots:**
1. Check if any of the 1,814 attempts returned HTTP 200 — a single success means account compromise
2. Look up `23.22.63.114` in threat intel — check VirusTotal, AbuseIPDB for prior brute force reports
3. Check for the same source IP hitting other hosts in the environment

**AI-drafted triage note:**
> Source IP `23.22.63.114` submitted 1,814 POST requests to the Joomla admin login page over 6 minutes, all returning HTTP 401. The request rate and mixed user-agent strings are consistent with automated brute force tooling. This maps to MITRE T1110.001. Priority pivot is confirming whether any attempt succeeded before assessing containment urgency.

---

## My independent analysis

**Checked for successful login:**
```spl
index=botsv1 sourcetype=stream:http src_ip=23.22.63.114 status=200
| table _time, uri, status, src_ip
```
Result: No HTTP 200 responses from this IP. Brute force did not succeed from this source.

**Threat intel pivot on source IP:**
```spl
index=botsv1 sourcetype=stream:http src_ip=23.22.63.114
| stats count by dest_ip, uri
```
Same IP also probed `/wp-admin/` and `/phpmyadmin/` on other hosts. Consistent with opportunistic scanning, not a targeted attack.

**Checked for IP in wider logs:**
AbuseIPDB (manual lookup): `23.22.63.114` reported 47 times for brute force and scanning activity. AWS-hosted IP — likely rented attack infrastructure.

**What AI got right:** Technique mapping, severity framing, and the critical pivot (check for HTTP 200) were all correct and direct.

**What I added:** Confirmed no successful login. Identified the IP as a scanner hitting multiple targets — reframes this from targeted attack to opportunistic noise, which changes the escalation priority.

---

## Disposition

**True Positive — High (downgraded from Critical)**

Automated brute force confirmed. No successful authentication. Opportunistic scanner, not targeted adversary. Block recommended; escalation not required.

**Actions taken:**
1. Recommended IP block at WAF/firewall level
2. Documented in ticket for pattern tracking
3. No Tier 2 escalation — no account compromise detected

---

## Final incident ticket

**Summary:** Automated brute force attack from `23.22.63.114` against Joomla admin panel. 1,814 attempts in 6 minutes, no successful authentication. IP confirmed as known scanner in threat intel.

**Timeline:**
- `14:00 UTC` — First POST request from `23.22.63.114`
- `14:06 UTC` — Last attempt, 1,814 total, all HTTP 401
- `14:09 UTC` — Alert triggered by failed login threshold rule
- `14:22 UTC` — Triage complete

**Affected assets:** `imreallynotbatman.com` web server (Joomla CMS)

**IOCs:**
- Source IP: `23.22.63.114` (AWS-hosted, AbuseIPDB flagged)
- Target path: `/joomla/administrator/index.php`
- Pattern: 1,814 POST requests / 6 minutes

**MITRE ATT&CK:** T1110.001

**Analyst disposition:** True Positive — no breach. Block and monitor.

**Reasoning:** Brute force confirmed by volume and rate. No HTTP 200 returned. IP is known scanner per AbuseIPDB. Joomla admin panel should not be publicly exposed — this is also a hardening recommendation.

**Recommended next steps:**
- Block `23.22.63.114` at perimeter
- Restrict `/joomla/administrator/` to trusted IPs only
- Enable account lockout policy on Joomla admin if not already configured
- Monitor for the same IP on other hosts

---

## Key takeaway

The AI immediately flagged the correct priority pivot — check for HTTP 200. That one query either escalates this to Critical or keeps it at High. That's experienced analyst thinking compressed into a prompt. My job was to run the query and make the call. Total triage time: **~6 minutes.**
