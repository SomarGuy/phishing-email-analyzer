> **SYNTHETIC SAMPLE.** This message was written for testing; the people, organisations, domains and IPs are fictional or reserved.

# Incident report: Update your direct deposit before Friday payroll

| Field | Value |
|---|---|
| Verdict | **LIKELY PHISHING** (risk score 75/100) |
| Message | H04-payroll-direct-deposit-change |
| From | "Payroll" <payroll[.]dept2026[@]freemail[.]example> |
| Reply-To / Return-Path | <payroll[.]updates[@]mail-desk[.]test> / <payroll[.]dept2026[@]freemail[.]example> |
| Date / origin IP | 2026-03-30 12:44:00Z / 198[.]51[.]100[.]15 |
| Authentication | SPF pass \| DKIM pass \| DMARC pass |
| ATT&CK | T1684.001 Social Engineering: Impersonation, T1684.002 Social Engineering: Email Spoofing, T1566.002 Phishing: Spearphishing Link, T1566.003 Phishing: Spearphishing via Service |

## Why

| Pts | Sev | Indicator | Detail |
|---|---|---|---|
| +25 | high | Display name matches a protected person or team, but the domain is not ours | Display name 'Payroll' matches protected name 'Payroll' (Finance) but the domain is freemail[.]example |
| +15 | medium | Reply-To goes to a different domain than From | Reply-To domain mail-desk[.]test differs from From domain freemail[.]example |
| +10 | high | Executive impersonation combined with payment or gift-card wording | Impersonated sender combined with a money request |
| +10 | medium | Invoice, payment or bank-detail wording | Payment/invoice wording: 'Update your direct deposit' |
| +10 | medium | Link goes through a URL shortener | short[.]test is a URL shortener; the destination is hidden |
| +5 | medium | Free-mail address using the name of a protected person, team or brand | Free-mail address payroll[.]dept2026[@]freemail[.]example uses the name 'Payroll' |

## Recommended response

- [ ] Confirm any request with the real person or team using a known phone number or chat.
- [ ] Do not reply; a reply would reach the Reply-To address, not the sender shown.
- [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
- [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
- [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
- [ ] If the user clicked or opened anything: reset their password, revoke active sessions, check MFA methods and mailbox rules, and isolate the device if an attachment was opened.

## Indicators (defanged)

| Type | Value | Context |
|---|---|---|
| email | payroll[.]dept2026[@]freemail[.]example | From address |
| domain | freemail[.]example | Sender domain |
| email | payroll[.]updates[@]mail-desk[.]test | Reply-To address |
| domain | mail-desk[.]test | Reply-To domain |
| ip | 198[.]51[.]100[.]15 | Origin of the Received chain |
| url | hxxps://short[.]test/Pr0ll | url_shortener |
| domain | short[.]test | Domain of a flagged URL |

## Ticket note (copy-ready)

```text
PHISHING TRIAGE - LIKELY PHISHING (risk 75/100)
Subject: Update your direct deposit before Friday payroll
From: "Payroll" <payroll[.]dept2026[@]freemail[.]example>
Reply-To: <payroll[.]updates[@]mail-desk[.]test>
Sent: 2026-03-30 12:44:00Z | Origin IP: 198[.]51[.]100[.]15
Authentication: SPF pass | DKIM pass | DMARC pass
Why it was flagged:
  1. Display name matches a protected person or team, but the domain is not ours (+25) - Display name 'Payroll' matches protected name 'Payroll' (Finance) but the domain is freemail[.]example
  2. Reply-To goes to a different domain than From (+15) - Reply-To domain mail-desk[.]test differs from From domain freemail[.]example
  3. Invoice, payment or bank-detail wording (+10) - Payment/invoice wording: 'Update your direct deposit'
  4. Link goes through a URL shortener (+10) - short[.]test is a URL shortener; the destination is hidden
  5. Free-mail address using the name of a protected person, team or brand (+5) - Free-mail address payroll[.]dept2026[@]freemail[.]example uses the name 'Payroll'
Suspicious links: hxxps://short[.]test/Pr0ll
ATT&CK: T1684.001, T1684.002, T1566.002, T1566.003
Recommended actions:
  [ ] Confirm any request with the real person or team using a known phone number or chat.
  [ ] Do not reply; a reply would reach the Reply-To address, not the sender shown.
  [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
  [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
  [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
  [ ] If the user clicked or opened anything: reset their password, revoke active sessions, check MFA methods and mailbox rules, and isolate the device if an attachment was opened.
User impact: UNKNOWN - ask the recipient whether they clicked a link, opened an attachment, entered credentials or replied.
Method: phishanalyzer 1.0.0 static analysis (nothing was opened, executed or fetched).
```

_Generated by phishanalyzer 1.0.0. Static analysis only: nothing was opened, executed or fetched._
