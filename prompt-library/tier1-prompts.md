# Tier 1 SOC Analyst — AI Prompt Library

> These are structured prompts I use with an LLM assistant during Tier 1 triage.  
> Each prompt is designed to extract specific, actionable context — not generic summaries.  
> **The AI provides context. I make the call.**

---

## Prompt 1 — Suspicious process / LOLBins triage

Use when: a SIEM alert flags an unusual parent-child process relationship or known living-off-the-land binary (LOLBin).

```
You are a SOC analyst assistant helping with Tier 1 triage.

Alert details:
- Event ID: [e.g. 4688]
- Parent process: [e.g. winword.exe]
- Child process: [e.g. cmd.exe]
- Command line args: [paste full args]
- User: [username]
- Hostname: [hostname]
- Timestamp: [timestamp]

Provide:
1. Is this behavior suspicious? Why or why not?
2. MITRE ATT&CK technique ID and name this most likely maps to
3. Severity: Low / Medium / High — with reasoning
4. Next 3 log sources or pivots I should investigate
5. Draft a one-paragraph Tier 1 triage note in plain English

Do not assume malicious intent without clear indicators. Flag uncertainty.
```

---

## Prompt 2 — Obfuscated PowerShell decoder

Use when: a SIEM alert contains base64-encoded or otherwise obfuscated PowerShell commands.

```
You are a SOC analyst assistant.

I have the following obfuscated PowerShell command from a SIEM alert:
[paste full command]

Provide:
1. Decode the command and show the plaintext version
2. Explain in plain English what this command does
3. What attacker objective does this serve? (e.g. persistence, exfiltration, lateral movement)
4. What artifacts would this leave on the host? (registry keys, files, network connections)
5. MITRE ATT&CK technique ID this maps to
6. Recommended immediate action: monitor / isolate / escalate

Flag if the decoded output is itself obfuscated or requires further decoding.
```

---

## Prompt 3 — Phishing email header analysis

Use when: a user reports a suspicious email or a mail gateway alert fires.

```
You are a SOC analyst assistant helping triage a reported phishing email.

Email header fields:
- From: [display name and address]
- Reply-To: [if different]
- Return-Path: [address]
- Received: [paste full received chain]
- Subject: [subject line]
- SPF result: [pass/fail/softfail]
- DKIM result: [pass/fail]
- DMARC result: [pass/fail]

Email body summary: [brief description or paste body]

Provide:
1. Spoofing indicators — is the sender who they claim to be?
2. Social engineering technique used (urgency, authority, fear, etc.)
3. Suspicious links or attachments noted
4. Likelihood this is phishing: Low / Medium / High — with reasoning
5. Recommended user communication (one sentence, plain English)
6. Suggested containment action
```

---

## Prompt 4 — IOC enrichment summary

Use when: you have a flagged IP, domain, or file hash and need to build enrichment context before writing a ticket.

```
You are a SOC analyst assistant.

I have the following IOC flagged in our SIEM:
- Type: [IP address / domain / file hash]
- Value: [paste IOC]
- Context: [where it appeared — e.g. outbound connection from host X at time Y]

Provide:
1. What should I look for when checking this IOC in VirusTotal / Shodan / AbuseIPDB?
2. What threat categories is this IOC type commonly associated with?
3. What SIEM queries should I run to check for related activity?
4. Draft an IOC enrichment note for my incident ticket (3-4 sentences)
5. Recommended disposition: block / monitor / escalate — with reasoning
```

---

## Prompt 5 — MITRE ATT&CK technique lookup and context

Use when: you've identified a technique ID but need depth before escalating.

```
You are a SOC analyst assistant.

I am investigating an alert that appears to involve MITRE ATT&CK technique: [T####.###]

Provide:
1. Plain English explanation of what this technique does (2-3 sentences)
2. Common tools or malware families that use this technique
3. What evidence would confirm this technique is being used?
4. What evidence would rule it out (false positive indicators)?
5. Recommended Tier 1 response actions
6. What should I include in my escalation note to Tier 2?
```

---

## Prompt 6 — Structured incident ticket generator

Use when: you've completed triage and need to write a clean, Tier-2-ready incident ticket fast.

```
You are a SOC analyst assistant. Convert my raw triage notes into a structured incident ticket.

Raw notes:
[paste your informal notes, alert details, and findings]

Generate a ticket with these sections:
- Summary (2 sentences max)
- Timeline (bullet points, chronological)
- Affected assets (hostname, IP, user)
- IOCs identified (IPs, domains, hashes, process names)
- MITRE ATT&CK technique(s)
- Analyst disposition: [True Positive / False Positive / Escalated]
- Reasoning (why I made this call)
- Recommended next steps for Tier 2

Write in professional, plain English. No jargon without explanation.
Flag any gaps in the evidence I should fill before closing the ticket.
```

---

## Usage notes

- Always verify AI output independently before finalizing disposition
- Never paste customer PII, credentials, or production system data into external LLMs
- AI output is a starting point — your reasoning is what goes in the ticket
- If AI output contradicts your gut, investigate further before trusting either

---

*Maintained by Shyam Srujan | [github.com/shyamsrujan/soc-ai-playbook](https://github.com/shyamsrujan/soc-ai-playbook)*
