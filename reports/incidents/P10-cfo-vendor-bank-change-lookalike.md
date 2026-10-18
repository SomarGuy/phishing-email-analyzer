> **SYNTHETIC SAMPLE.** This message was written for testing; the people, organisations, domains and IPs are fictional or reserved.

# Incident report: Urgent wire transfer - new bank details

| Field | Value |
|---|---|
| Verdict | **LIKELY PHISHING** (risk score 100/100) |
| Message | P10-cfo-vendor-bank-change-lookalike |
| From | "Marcus Cole" <marcus[.]cole[@]northwind-analytlcs[.]example> |
| Reply-To / Return-Path | <m[.]cole[.]finance[@]freemail[.]example> / <marcus[.]cole[@]northwind-analytlcs[.]example> |
| Date / origin IP | 2026-03-14 19:37:00Z / 198[.]51[.]100[.]99 |
| Authentication | SPF fail \| DKIM none \| DMARC fail |
| ATT&CK | T1684.001 Social Engineering: Impersonation, T1684.002 Social Engineering: Email Spoofing |

## Why

| Pts | Sev | Indicator | Detail |
|---|---|---|---|
| +30 | high | Sender domain imitates a protected brand or our own domain | From domain northwind-analytlcs[.]example imitates Northwind Analytics (typo of the brand name) |
| +20 | high | Business-email-compromise style request | Business-email-compromise phrasing: 'Do not call', 'I am travelling', 'new bank details' |
| +20 | high | DMARC failed for the From domain | DMARC fail for northwind-analytlcs[.]example (computed from SPF/DKIM alignment) |
| +15 | high | Display name matches a protected person or team, but the domain is not ours | Display name 'Marcus Cole' matches protected name 'Marcus Cole' (CFO) but the domain is northwind-analytlcs[.]example |
| +15 | high | SPF failed: the sending server is not authorised for the envelope domain | SPF result 'fail' for northwind-analytlcs[.]example (offline (synthetic DNS fixtures)) |
| +10 | high | Executive impersonation combined with payment or gift-card wording | Impersonated sender combined with a money request |
| +10 | high | Claims a protected identity and fails authentication | Impersonated sender that also fails authentication |
| +10 | medium | Invoice, payment or bank-detail wording | Payment/invoice wording: 'wire transfer' |

_1 lower-weight indicator(s) omitted; see analysis.json._

## Recommended response

- [ ] Add the lookalike domain to the mail gateway block list.
- [ ] Verify any payment or bank-detail change by phone with a known number before acting.
- [ ] Confirm any request with the real person or team using a known phone number or chat.
- [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
- [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
- [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
- [ ] If the user clicked or opened anything: reset their password, revoke active sessions, check MFA methods and mailbox rules, and isolate the device if an attachment was opened.

## Indicators (defanged)

| Type | Value | Context |
|---|---|---|
| email | marcus[.]cole[@]northwind-analytlcs[.]example | From address |
| domain | northwind-analytlcs[.]example | Sender domain |
| email | m[.]cole[.]finance[@]freemail[.]example | Reply-To address |
| domain | freemail[.]example | Reply-To domain |
| ip | 198[.]51[.]100[.]99 | Origin of the Received chain |

## Ticket note (copy-ready)

```text
PHISHING TRIAGE - LIKELY PHISHING (risk 100/100)
Subject: Urgent wire transfer - new bank details
From: "Marcus Cole" <marcus[.]cole[@]northwind-analytlcs[.]example>
Reply-To: <m[.]cole[.]finance[@]freemail[.]example>
Sent: 2026-03-14 19:37:00Z | Origin IP: 198[.]51[.]100[.]99
Authentication: SPF fail | DKIM none | DMARC fail
Why it was flagged:
  1. Sender domain imitates a protected brand or our own domain (+30) - From domain northwind-analytlcs[.]example imitates Northwind Analytics (typo of the brand name)
  2. Business-email-compromise style request (+20) - Business-email-compromise phrasing: 'Do not call', 'I am travelling', 'new bank details'
  3. DMARC failed for the From domain (+20) - DMARC fail for northwind-analytlcs[.]example (computed from SPF/DKIM alignment)
  4. Display name matches a protected person or team, but the domain is not ours (+15) - Display name 'Marcus Cole' matches protected name 'Marcus Cole' (CFO) but the domain is northwind-analytlcs[.]example
  5. SPF failed: the sending server is not authorised for the envelope domain (+15) - SPF result 'fail' for northwind-analytlcs[.]example (offline (synthetic DNS fixtures))
ATT&CK: T1684.001, T1684.002
Recommended actions:
  [ ] Add the lookalike domain to the mail gateway block list.
  [ ] Verify any payment or bank-detail change by phone with a known number before acting.
  [ ] Confirm any request with the real person or team using a known phone number or chat.
  [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
  [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
  [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
User impact: UNKNOWN - ask the recipient whether they clicked a link, opened an attachment, entered credentials or replied.
Method: phishanalyzer 1.0.0 static analysis (nothing was opened, executed or fetched).
```

_Generated by phishanalyzer 1.0.0. Static analysis only: nothing was opened, executed or fetched._
