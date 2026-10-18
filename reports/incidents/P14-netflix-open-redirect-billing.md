> **SYNTHETIC SAMPLE.** This message was written for testing; the people, organisations, domains and IPs are fictional or reserved.

# Incident report: Payment failed - update your payment details

| Field | Value |
|---|---|
| Verdict | **LIKELY PHISHING** (risk score 100/100) |
| Message | P14-netflix-open-redirect-billing |
| From | "Netflix Billing" <billing[@]nf-account-help[.]test> |
| Reply-To / Return-Path | (none) / <billing[@]nf-account-help[.]test> |
| Date / origin IP | 2026-03-18 20:03:00Z / 198[.]51[.]100[.]120 |
| Authentication | SPF fail \| DKIM none \| DMARC fail |
| ATT&CK | T1684.001 Social Engineering: Impersonation, T1684.002 Social Engineering: Email Spoofing, T1598.003 Phishing for Information: Spearphishing Link, T1566.002 Phishing: Spearphishing Link |

## Why

| Pts | Sev | Indicator | Detail |
|---|---|---|---|
| +25 | high | Display name uses a brand name but the sender domain is not that brand's | Display name uses 'Netflix' but the sender domain is nf-account-help[.]test |
| +20 | high | DMARC failed for the From domain | DMARC fail for nf-account-help[.]test (Authentication-Results) |
| +15 | high | SPF failed: the sending server is not authorised for the envelope domain | SPF result 'fail' for nf-account-help[.]test (Authentication-Results) |
| +12 | medium | Asks the reader to verify, confirm or reset credentials | Credential-harvesting wording: 'update your payment details' |
| +10 | high | Executive impersonation combined with payment or gift-card wording | Impersonated sender combined with a money request |
| +10 | high | Claims a protected identity and fails authentication | Impersonated sender that also fails authentication |
| +10 | medium | Invoice, payment or bank-detail wording | Payment/invoice wording: 'Payment failed', 'update your payment' |
| +10 | medium | Link carries a redirect parameter to a different site | Parameter 'redirect' carries another destination (netf1ix-billing.test) |

_2 lower-weight indicator(s) omitted; see analysis.json._

## Recommended response

- [ ] Report the impersonated brand if it offers an abuse mailbox.
- [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
- [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
- [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
- [ ] If the user clicked or opened anything: reset their password, revoke active sessions, check MFA methods and mailbox rules, and isolate the device if an attachment was opened.

## Indicators (defanged)

| Type | Value | Context |
|---|---|---|
| email | billing[@]nf-account-help[.]test | From address |
| domain | nf-account-help[.]test | Sender domain |
| ip | 198[.]51[.]100[.]120 | Origin of the Received chain |
| url | hxxps://trusted-news[.]example/out?redirect=https%3A%2F%2Fnetf1ix-billing.test%2Flogin | url_redirect_param; url_login_keywords |
| domain | trusted-news[.]example | Domain of a flagged URL |

## Ticket note (copy-ready)

```text
PHISHING TRIAGE - LIKELY PHISHING (risk 100/100)
Subject: Payment failed - update your payment details
From: "Netflix Billing" <billing[@]nf-account-help[.]test>
Sent: 2026-03-18 20:03:00Z | Origin IP: 198[.]51[.]100[.]120
Authentication: SPF fail | DKIM none | DMARC fail
Why it was flagged:
  1. Display name uses a brand name but the sender domain is not that brand's (+25) - Display name uses 'Netflix' but the sender domain is nf-account-help[.]test
  2. DMARC failed for the From domain (+20) - DMARC fail for nf-account-help[.]test (Authentication-Results)
  3. SPF failed: the sending server is not authorised for the envelope domain (+15) - SPF result 'fail' for nf-account-help[.]test (Authentication-Results)
  4. Asks the reader to verify, confirm or reset credentials (+12) - Credential-harvesting wording: 'update your payment details'
  5. Invoice, payment or bank-detail wording (+10) - Payment/invoice wording: 'Payment failed', 'update your payment'
Suspicious links: hxxps://trusted-news[.]example/out?redirect=https%3A%2F%2Fnetf1ix-billing.test%2Flogin
ATT&CK: T1684.001, T1684.002, T1598.003, T1566.002
Recommended actions:
  [ ] Report the impersonated brand if it offers an abuse mailbox.
  [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
  [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
  [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
  [ ] If the user clicked or opened anything: reset their password, revoke active sessions, check MFA methods and mailbox rules, and isolate the device if an attachment was opened.
User impact: UNKNOWN - ask the recipient whether they clicked a link, opened an attachment, entered credentials or replied.
Method: phishanalyzer 1.0.0 static analysis (nothing was opened, executed or fetched).
```

_Generated by phishanalyzer 1.0.0. Static analysis only: nothing was opened, executed or fetched._
