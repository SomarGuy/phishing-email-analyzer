> **SYNTHETIC SAMPLE.** This message was written for testing; the people, organisations, domains and IPs are fictional or reserved.

# Incident report: Your mailbox is full - verify your account

| Field | Value |
|---|---|
| Verdict | **LIKELY PHISHING** (risk score 100/100) |
| Message | P02-microsoft-idn-homograph |
| From | "Microsoft 365 Admin" <admin[@]m365-notices[.]test> |
| Reply-To / Return-Path | (none) / <admin[@]m365-notices[.]test> |
| Date / origin IP | 2026-03-06 22:09:00Z / 198[.]51[.]100[.]211 |
| Authentication | SPF softfail \| DKIM none \| DMARC fail |
| ATT&CK | T1684.001 Social Engineering: Impersonation, T1566.002 Phishing: Spearphishing Link, T1204.001 User Execution: Malicious Link, T1684.002 Social Engineering: Email Spoofing, T1598.003 Phishing for Information: Spearphishing Link |

## Why

| Pts | Sev | Indicator | Detail |
|---|---|---|---|
| +25 | high | Display name uses a brand name but the sender domain is not that brand's | Display name uses 'Microsoft' but the sender domain is m365-notices[.]test |
| +25 | high | Link uses look-alike (homograph) characters | Internationalised host xn--micrsft-djgb.invalid: label 'micrоsоft' mixes scripts (cyrillic, latin) |
| +20 | high | DMARC failed for the From domain | DMARC fail for m365-notices[.]test (Authentication-Results) |
| +12 | medium | Asks the reader to verify, confirm or reset credentials | Credential-harvesting wording: 'verify your account', 'mailbox is full' |
| +10 | high | Credential or urgency lure combined with a deceptive link | Persuasion wording plus a deceptive link |
| +10 | high | Claims a protected identity and fails authentication | Impersonated sender that also fails authentication |
| +8 | medium | SPF softfail | SPF softfail for m365-notices[.]test (Authentication-Results) |
| +8 | low | Link uses a top-level domain often abused for phishing | Top-level domain .invalid is heavily abused |

_1 lower-weight indicator(s) omitted; see analysis.json._

## Recommended response

- [ ] Report the impersonated brand if it offers an abuse mailbox.
- [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
- [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
- [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
- [ ] If the user clicked or opened anything: reset their password, revoke active sessions, check MFA methods and mailbox rules, and isolate the device if an attachment was opened.

## Indicators (defanged)

| Type | Value | Context |
|---|---|---|
| email | admin[@]m365-notices[.]test | From address |
| domain | m365-notices[.]test | Sender domain |
| ip | 198[.]51[.]100[.]211 | Origin of the Received chain |
| url | hxxps://xn--micrsft-djgb[.]invalid/owa/verify | url_idn_homograph; url_suspicious_tld; url_login_keywords |
| domain | micrоsоft[.]invalid | Domain of a flagged URL |

## Ticket note (copy-ready)

```text
PHISHING TRIAGE - LIKELY PHISHING (risk 100/100)
Subject: Your mailbox is full - verify your account
From: "Microsoft 365 Admin" <admin[@]m365-notices[.]test>
Sent: 2026-03-06 22:09:00Z | Origin IP: 198[.]51[.]100[.]211
Authentication: SPF softfail | DKIM none | DMARC fail
Why it was flagged:
  1. Display name uses a brand name but the sender domain is not that brand's (+25) - Display name uses 'Microsoft' but the sender domain is m365-notices[.]test
  2. Link uses look-alike (homograph) characters (+25) - Internationalised host xn--micrsft-djgb.invalid: label 'micrоsоft' mixes scripts (cyrillic, latin)
  3. DMARC failed for the From domain (+20) - DMARC fail for m365-notices[.]test (Authentication-Results)
  4. Asks the reader to verify, confirm or reset credentials (+12) - Credential-harvesting wording: 'verify your account', 'mailbox is full'
  5. SPF softfail (+8) - SPF softfail for m365-notices[.]test (Authentication-Results)
Suspicious links: hxxps://xn--micrsft-djgb[.]invalid/owa/verify
ATT&CK: T1684.001, T1566.002, T1204.001, T1684.002, T1598.003
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
