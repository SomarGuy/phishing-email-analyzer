> **SYNTHETIC SAMPLE.** This message was written for testing; the people, organisations, domains and IPs are fictional or reserved.

# Incident report: Password expires in 24 hours - keep your current password

| Field | Value |
|---|---|
| Verdict | **LIKELY PHISHING** (risk score 87/100) |
| Message | P11-helpdesk-password-reset-spoof |
| From | "IT Help Desk" <helpdesk[@]northwind-analytics-support[.]test> |
| Reply-To / Return-Path | (none) / <helpdesk[@]northwind-analytics-support[.]test> |
| Date / origin IP | 2026-03-15 07:50:00Z / 203[.]0[.]113[.]240 |
| Authentication | SPF none \| DKIM none \| DMARC none |
| ATT&CK | T1684.001 Social Engineering: Impersonation, T1598.003 Phishing for Information: Spearphishing Link, T1566.002 Phishing: Spearphishing Link |

## Why

| Pts | Sev | Indicator | Detail |
|---|---|---|---|
| +30 | high | Sender domain imitates a protected brand or our own domain | From domain northwind-analytics-support[.]test imitates Northwind Analytics (brand name inside the domain) |
| +15 | high | Display name matches a protected person or team, but the domain is not ours | Display name 'IT Help Desk' matches protected name 'IT Help Desk' (IT) but the domain is northwind-analytics-support[.]test |
| +12 | medium | Asks the reader to verify, confirm or reset credentials | Credential-harvesting wording: 'Password expire', 'keep your current password', 'Sign in to keep' |
| +12 | medium | Brand name used inside a domain it does not own | Northwind Analytics used inside the domain northwind-analytics-support[.]test |
| +10 | high | Credential or urgency lure combined with a deceptive link | Persuasion wording plus a deceptive link |
| +8 | low | Urgent or threatening wording | Pressure/urgency wording: 'within 24 hours', 'within 24 hours' |

## Recommended response

- [ ] Add the lookalike domain to the mail gateway block list.
- [ ] Confirm any request with the real person or team using a known phone number or chat.
- [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
- [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
- [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
- [ ] If the user clicked or opened anything: reset their password, revoke active sessions, check MFA methods and mailbox rules, and isolate the device if an attachment was opened.

## Indicators (defanged)

| Type | Value | Context |
|---|---|---|
| email | helpdesk[@]northwind-analytics-support[.]test | From address |
| domain | northwind-analytics-support[.]test | Sender domain |
| ip | 203[.]0[.]113[.]240 | Origin of the Received chain |
| url | hxxps://sso[.]northwind-analytics-support[.]test/login?user=alex.morgan | url_brand_in_domain |

## Ticket note (copy-ready)

```text
PHISHING TRIAGE - LIKELY PHISHING (risk 87/100)
Subject: Password expires in 24 hours - keep your current password
From: "IT Help Desk" <helpdesk[@]northwind-analytics-support[.]test>
Sent: 2026-03-15 07:50:00Z | Origin IP: 203[.]0[.]113[.]240
Authentication: SPF none | DKIM none | DMARC none
Why it was flagged:
  1. Sender domain imitates a protected brand or our own domain (+30) - From domain northwind-analytics-support[.]test imitates Northwind Analytics (brand name inside the domain)
  2. Display name matches a protected person or team, but the domain is not ours (+15) - Display name 'IT Help Desk' matches protected name 'IT Help Desk' (IT) but the domain is northwind-analytics-support[.]test
  3. Asks the reader to verify, confirm or reset credentials (+12) - Credential-harvesting wording: 'Password expire', 'keep your current password', 'Sign in to keep'
  4. Brand name used inside a domain it does not own (+12) - Northwind Analytics used inside the domain northwind-analytics-support[.]test
  5. Urgent or threatening wording (+8) - Pressure/urgency wording: 'within 24 hours', 'within 24 hours'
Suspicious links: hxxps://sso[.]northwind-analytics-support[.]test/login?user=alex.morgan
ATT&CK: T1684.001, T1598.003, T1566.002
Recommended actions:
  [ ] Add the lookalike domain to the mail gateway block list.
  [ ] Confirm any request with the real person or team using a known phone number or chat.
  [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
  [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
  [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
  [ ] If the user clicked or opened anything: reset their password, revoke active sessions, check MFA methods and mailbox rules, and isolate the device if an attachment was opened.
User impact: UNKNOWN - ask the recipient whether they clicked a link, opened an attachment, entered credentials or replied.
Method: phishanalyzer 1.0.0 static analysis (nothing was opened, executed or fetched).
```

_Generated by phishanalyzer 1.0.0. Static analysis only: nothing was opened, executed or fetched._
