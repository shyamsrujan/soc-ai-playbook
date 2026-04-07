# SOC AI Playbook — Shyam Srujan

> **AI-augmented Tier 1 SOC analyst triage workflow.**  
> Real attack data. Structured prompts. Human judgment. Documented proof of work.

---

## What this is

This repository documents how I use AI as a **force multiplier** in Tier 1 SOC analyst workflows — not to replace analyst judgment, but to compress the time between alert and informed decision.

Built using the **Splunk Boss of the SOC (BOTS) v1 dataset** — a real-world attack simulation used in security training globally.

**Stack:** Splunk Enterprise · Claude (LLM) · MITRE ATT&CK · structured prompt engineering

---

## The workflow

```
Raw SIEM Alert
      │
      ▼
Structured AI Prompt  ←── prompt-library/tier1-prompts.md
      │
      ▼
AI Output: MITRE mapping · severity · pivot recommendations
      │
      ▼
Independent Analyst Verification (Splunk queries, log pivot)
      │
      ▼
Disposition: True Positive / False Positive / Escalate
      │
      ▼
Structured Incident Ticket
```

AI handles: context mapping, technique identification, ticket scaffolding.  
**I handle: the call.**

---

## Investigations

| # | Finding | MITRE | Disposition |
|---|---|---|---|
| 01 | Ransomware VSS deletion — `vssadmin delete shadows /all /quiet` on `we8105desk` | T1490, T1059.003 | True Positive — Critical |
| 02 | Malware staging via Microsoft CDN — 35 HTTP connections, OneDrive C2 pattern, masqueraded Windows Update URI | T1102.002, T1036, T1041 | True Positive — High, Escalated |

**Key finding:** These two incidents are correlated — staging (Investigation 02) preceded ransomware detonation (Investigation 01) by 14 days. Single attacker campaign with confirmed dwell time.

→ [Full investigation report](INVESTIGATION-REPORT.md)  
→ [Investigation 01 — Ransomware VSS deletion](investigations/01-ransomware-triage.md)  
→ [Investigation 02 — Malware staging via cloud infrastructure](investigations/02-malware-staging-triage.md)

---

## Prompt library

Six production-ready prompts for Tier 1 triage scenarios.

→ [prompt-library/tier1-prompts.md](prompt-library/tier1-prompts.md)

Covers: suspicious process triage · PowerShell decoding · phishing analysis · IOC enrichment · MITRE lookup · ticket generation

---

## Screenshots

Real Splunk output from the BOTS v1 dataset:

- `screenshots/01-vssadmin-splunk-evidence.png` — vssadmin command confirmed in WinEventLog
- `screenshots/02-http-malware-staging-splunk.png` — 35 HTTP connections to Microsoft CDN
- `screenshots/03-claude-triage-output.png` — AI triage analysis output

---

## Why this matters

Tier 1 SOC analysts who use AI effectively:
- Triage faster without sacrificing accuracy
- Write cleaner tickets Tier 2 can act on immediately
- Map alerts to adversary TTPs instead of just closing tickets

This playbook is proof of that workflow — built on real data, not theory.

---

## About

**Shyam Srujan** — M.S. Computer Science, Illinois Institute of Technology  
Former App Engineering Associate, Accenture  
Volunteer Cybersecurity Analyst @ CDF  
Seeking: SOC Analyst · InfoSec Analyst · Security Engineer roles

[LinkedIn](https://linkedin.com/in/shyamsrujan) · [Portfolio](https://portfolio-rose-ten-95.vercel.app)

---

> *"AI compresses the repetitive volume work. My value is the judgment, the accountability, and the technical depth to go beyond what the automation surfaces."*

---

*All data from the public Splunk BOTS v1 dataset. Hostnames, usernames, and IPs are from the fictional WAYNECORPINC simulation environment.*
