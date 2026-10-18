> **SYNTHETIC SAMPLE.** This message was written for testing; the people, organisations, domains and IPs are fictional or reserved.

# Incident report: Action required: unusual sign-in detected

| Field | Value |
|---|---|
| Verdict | **LIKELY PHISHING** (risk score 100/100) |
| Message | P01-paypal-lookalike-credential |
| From | "PayPal Security" <service[@]paypa1-secure[.]test> |
| Reply-To / Return-Path | (none) / <bounce[@]paypa1-secure[.]test> |
| Date / origin IP | 2026-03-04 02:11:00Z / 203[.]0[.]113[.]200 |
| Authentication | SPF fail \| DKIM none \| DMARC fail |
| ATT&CK | T1684.001 Social Engineering: Impersonation, T1566.002 Phishing: Spearphishing Link, T1204.001 User Execution: Malicious Link, T1684.002 Social Engineering: Email Spoofing, T1598.003 Phishing for Information: Spearphishing Link |

## Why

| Pts | Sev | Indicator | Detail |
|---|---|---|---|
| +30 | high | Sender domain imitates a protected brand or our own domain | From domain paypa1-secure[.]test imitates PayPal (brand name inside the domain) |
| +25 | high | Link text shows one address but the link goes to another | Link text shows www[.]paypal[.]com but the link goes to paypa1-secure[.]test |
| +20 | high | DMARC failed for the From domain | DMARC fail for paypa1-secure[.]test (Authentication-Results) |
| +15 | high | Display name uses a brand name but the sender domain is not that brand's | Display name uses 'PayPal' but the sender domain is paypa1-secure[.]test |
| +15 | high | SPF failed: the sending server is not authorised for the envelope domain | SPF result 'fail' for paypa1-secure[.]test (Authentication-Results) |
| +12 | medium | Asks the reader to verify, confirm or reset credentials | Credential-harvesting wording: 'Verify your account', 'unusual sign-in' |
| +12 | medium | Brand name used inside a domain it does not own | PayPal used inside the domain paypa1-secure[.]test |
| +10 | high | Credential or urgency lure combined with a deceptive link | Persuasion wording plus a deceptive link |

_3 lower-weight indicator(s) omitted; see analysis.json._

## Recommended response

- [ ] Add the lookalike domain to the mail gateway block list.
- [ ] Report the impersonated brand if it offers an abuse mailbox.
- [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
- [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
- [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
- [ ] If the user clicked or opened anything: reset their password, revoke active sessions, check MFA methods and mailbox rules, and isolate the device if an attachment was opened.

## Indicators (defanged)

| Type | Value | Context |
|---|---|---|
| email | service[@]paypa1-secure[.]test | From address |
| domain | paypa1-secure[.]test | Sender domain |
| email | bounce[@]paypa1-secure[.]test | Return-Path address |
| ip | 203[.]0[.]113[.]200 | Origin of the Received chain |
| url | hxxps://paypa1-secure[.]test/signin?id=88213 | url_brand_in_domain; url_text_mismatch |
| url | hxxps://www[.]paypal[.]com/verify | url_login_keywords |
| domain | paypal[.]com | Domain of a flagged URL |

## Ticket note (copy-ready)

```text
PHISHING TRIAGE - LIKELY PHISHING (risk 100/100)
Subject: Action required: unusual sign-in detected
From: "PayPal Security" <service[@]paypa1-secure[.]test>
Return-Path: <bounce[@]paypa1-secure[.]test>
Sent: 2026-03-04 02:11:00Z | Origin IP: 203[.]0[.]113[.]200
Authentication: SPF fail | DKIM none | DMARC fail
Why it was flagged:
  1. Sender domain imitates a protected brand or our own domain (+30) - From domain paypa1-secure[.]test imitates PayPal (brand name inside the domain)
  2. Link text shows one address but the link goes to another (+25) - Link text shows www[.]paypal[.]com but the link goes to paypa1-secure[.]test
  3. DMARC failed for the From domain (+20) - DMARC fail for paypa1-secure[.]test (Authentication-Results)
  4. Display name uses a brand name but the sender domain is not that brand's (+15) - Display name uses 'PayPal' but the sender domain is paypa1-secure[.]test
  5. SPF failed: the sending server is not authorised for the envelope domain (+15) - SPF result 'fail' for paypa1-secure[.]test (Authentication-Results)
Suspicious links: hxxps://paypa1-secure[.]test/signin?id=88213; hxxps://www[.]paypal[.]com/verify
ATT&CK: T1684.001, T1566.002, T1204.001, T1684.002, T1598.003
Recommended actions:
  [ ] Add the lookalike domain to the mail gateway block list.
  [ ] Report the impersonated brand if it offers an abuse mailbox.
  [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
  [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
  [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
  [ ] If the user clicked or opened anything: reset their password, revoke active sessions, check MFA methods and mailbox rules, and isolate the device if an attachment was opened.
User impact: UNKNOWN - ask the recipient whether they clicked a link, opened an attachment, entered credentials or replied.
Method: phishanalyzer 1.0.0 static analysis (nothing was opened, executed or fetched).
```

_Generated by phishanalyzer 1.0.0. Static analysis only: nothing was opened, executed or fetched._
