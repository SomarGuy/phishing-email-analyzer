> **SYNTHETIC SAMPLE.** This message was written for testing; the people, organisations, domains and IPs are fictional or reserved.

# Incident report: Action required: re-validate your account with MFA

| Field | Value |
|---|---|
| Verdict | **LIKELY PHISHING** (risk score 100/100) |
| Message | P12-mfa-qr-code-phish |
| From | "Microsoft Security" <no-reply[@]secure-notify[.]test> |
| Reply-To / Return-Path | (none) / <no-reply[@]secure-notify[.]test> |
| Date / origin IP | 2026-03-16 04:18:00Z / 198[.]51[.]100[.]188 |
| Authentication | SPF fail \| DKIM none \| DMARC fail |
| ATT&CK | T1684.001 Social Engineering: Impersonation, T1684.002 Social Engineering: Email Spoofing, T1566.002 Phishing: Spearphishing Link, T1598.003 Phishing for Information: Spearphishing Link |

## Why

| Pts | Sev | Indicator | Detail |
|---|---|---|---|
| +25 | high | Display name uses a brand name but the sender domain is not that brand's | Display name uses 'Microsoft' but the sender domain is secure-notify[.]test |
| +20 | high | DMARC failed for the From domain | DMARC fail for secure-notify[.]test (Authentication-Results) |
| +15 | medium | Asks the reader to scan a QR code | QR-code instruction with an image: 'Scan the QR', 'QR code' |
| +15 | high | SPF failed: the sending server is not authorised for the envelope domain | SPF result 'fail' for secure-notify[.]test (Authentication-Results) |
| +12 | medium | Asks the reader to verify, confirm or reset credentials | Credential-harvesting wording: 're-validate your account' |
| +10 | high | Claims a protected identity and fails authentication | Impersonated sender that also fails authentication |
| +8 | low | Urgent or threatening wording | Pressure/urgency wording: 'within 24 hours', 'Action required', 'within 24 hours' |

## Recommended response

- [ ] Report the impersonated brand if it offers an abuse mailbox.
- [ ] Do not scan the QR code. Ask the user whether they did; if so, treat the destination as a phishing site.
- [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
- [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
- [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
- [ ] If the user clicked or opened anything: reset their password, revoke active sessions, check MFA methods and mailbox rules, and isolate the device if an attachment was opened.

## Indicators (defanged)

| Type | Value | Context |
|---|---|---|
| email | no-reply[@]secure-notify[.]test | From address |
| domain | secure-notify[.]test | Sender domain |
| ip | 198[.]51[.]100[.]188 | Origin of the Received chain |

## Ticket note (copy-ready)

```text
PHISHING TRIAGE - LIKELY PHISHING (risk 100/100)
Subject: Action required: re-validate your account with MFA
From: "Microsoft Security" <no-reply[@]secure-notify[.]test>
Sent: 2026-03-16 04:18:00Z | Origin IP: 198[.]51[.]100[.]188
Authentication: SPF fail | DKIM none | DMARC fail
Why it was flagged:
  1. Display name uses a brand name but the sender domain is not that brand's (+25) - Display name uses 'Microsoft' but the sender domain is secure-notify[.]test
  2. DMARC failed for the From domain (+20) - DMARC fail for secure-notify[.]test (Authentication-Results)
  3. Asks the reader to scan a QR code (+15) - QR-code instruction with an image: 'Scan the QR', 'QR code'
  4. SPF failed: the sending server is not authorised for the envelope domain (+15) - SPF result 'fail' for secure-notify[.]test (Authentication-Results)
  5. Asks the reader to verify, confirm or reset credentials (+12) - Credential-harvesting wording: 're-validate your account'
Attachments: qr.png (sha256 e878950f8091ec01...)
ATT&CK: T1684.001, T1684.002, T1566.002, T1598.003
Recommended actions:
  [ ] Report the impersonated brand if it offers an abuse mailbox.
  [ ] Do not scan the QR code. Ask the user whether they did; if so, treat the destination as a phishing site.
  [ ] Do not click links, open attachments or reply. If the user already did, treat it as an incident (see the steps marked 'if clicked').
  [ ] Report the message to the security team and keep the original (.eml with full headers) as evidence; do not forward it as plain text.
  [ ] Block the sender address and the domains/URLs below at the mail gateway and web proxy, then search other mailboxes for the same sender, subject, URL or attachment hash.
  [ ] If the user clicked or opened anything: reset their password, revoke active sessions, check MFA methods and mailbox rules, and isolate the device if an attachment was opened.
User impact: UNKNOWN - ask the recipient whether they clicked a link, opened an attachment, entered credentials or replied.
Method: phishanalyzer 1.0.0 static analysis (nothing was opened, executed or fetched).
```

_Generated by phishanalyzer 1.0.0. Static analysis only: nothing was opened, executed or fetched._
