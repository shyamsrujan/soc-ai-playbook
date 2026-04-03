# SOC AI Playbook — Shyam Srujan

> **AI-augmented Tier 1 SOC analyst triage workflow.**  
> Real attack scenarios. Structured prompts. Human judgment. Documented proof of work.

---

## What this is

This repository documents how I use AI as a **force multiplier** in Tier 1 SOC analyst workflows — not to replace analyst judgment, but to compress the time between alert and informed decision.

Built using the **Splunk Boss of the SOC (BOTS) v1 dataset** — a real-world attack simulation used in security training globally.

**Stack:** Splunk Free · Claude (LLM) · MITRE ATT&CK · structured prompt engineering

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

| # | Scenario | MITRE Technique | Disposition | File |
|---|----------|----------------|-------------|------|
| 1 | Ransomware — BOTS v1 | T1486 Data Encrypted for Impact | True Positive | [View →](investigations/01-ransomware-triage.md) |
| 2 | Brute Force / Credential Stuffing | T1110 Brute Force | True Positive | [View →](investigations/02-brute-force-triage.md) |
| 3 | C2 Beaconing / Phishing | T1071 App Layer Protocol | Escalated | [View →](investigations/03-c2-phishing-triage.md) |

---

## Prompt library

Six production-ready prompts for Tier 1 triage scenarios.

→ [prompt-library/tier1-prompts.md](prompt-library/tier1-prompts.md)

Prompts cover:
- Suspicious process / LOLBins alert triage
- Obfuscated PowerShell decoding
- Phishing email header analysis
- IOC enrichment summary
- MITRE ATT&CK technique mapping
- Structured incident ticket generation

---

## Demo video

→ [Watch the 3-minute triage walkthrough](demo-video-link.md)

Live screen recording: alert → AI prompt → Splunk pivot → disposition → ticket.

---

## Why this matters

Tier 1 SOC analysts who use AI effectively:
- Triage faster without sacrificing accuracy
- Write cleaner tickets Tier 2 can act on immediately
- Map alerts to adversary TTPs instead of just closing tickets

This playbook is my proof of that workflow — built on real data, not theory.

---

## About

**Shyam Srujan** — M.S. Computer Science, Illinois Institute of Technology (Dec 2025)  
Former App Engineering Associate, Accenture  
Pivoting into cybersecurity | SOC Analyst · InfoSec Analyst · Cyber Threat Analyst  
Volunteer Cybersecurity Analyst @ CDF

[LinkedIn](https://linkedin.com/in/shyamsrujan) · [Portfolio](https://portfolio-rose-ten-95.vercel.app)

---

> *"AI compresses the repetitive volume work. My value is the judgment, the accountability, and the technical depth to go beyond what the automation surfaces."*
