> **SYNTHETIC SAMPLE.** This message was written for testing; the people, organisations, domains and IPs are fictional or reserved.

# Incident report: Completed: please review and sign

| Field | Value |
|---|---|
| Verdict | **LIKELY PHISHING** (risk score 100/100) |
| Message | P03-docusign-html-credential-attachment |
| From | "DocuSign" <dse[@]docusgn-mail[.]test> |
| Reply-To / Return-Path | (none) / <dse[@]docusgn-mail[.]test> |
| Date / origin IP | 2026-03-07 12:30:00Z / 203[.]0[.]113[.]213 |
| Authentication | SPF fail \| DKIM none \| DMARC fail |
| ATT&CK | T1566.001 Phishing: Spearphishing Attachment, T1598.003 Phishing for Information: Spearphishing Link, T1684.001 Social Engineering: Impersonation, T1684.002 Social Engineering: Email Spoofing |

## Why

| Pts | Sev | Indicator | Detail |
|---|---|---|---|
| +35 | high | HTML attachment contains a password form | HTML attachment contains a password field posting to collect[.]docusgn-mail[.]test |
| +30 | high | Sender domain imitates a protected brand or our own domain | From domain docusgn-mail[.]test imitates DocuSign (typo of the brand name inside the domain) |
| +20 | high | DMARC failed for the From domain | DMARC fail for docusgn-mail[.]test (Authentication-Results) |
| +15 | high | Display name uses a brand name but the sender domain is not that brand's | Display name uses 'DocuSign' but the sender domain is docusgn-mail[.]test |
| +15 | high | SPF failed: the sending server is not authorised for the envelope domain | SPF result 'fail' for docusgn-mail[.]test (Authentication-Results) |
| +12 | medium | Asks the reader to verify, confirm or reset credentials | Credential-harvesting wording: 'sign in to view' |
| +12 | medium | HTML or SVG file attached | HTML attachment opens in the user's browser with local-file privileges |
| +10 | high | Claims a protected identity and fails authentication | Impersonated sender that also fails authentication |

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
| email | dse[@]docusgn-mail[.]test | From address |
| domain | docusgn-mail[.]test | Sender domain |
| ip | 203[.]0[.]113[.]213 | Origin of the Received chain |
| sha256 | 5ed86dc5629c0b6b7a30888a73a7e1b45a3a2e19fd5230a939d33c693a362950 | Attachment Agreement-7589.html: html_attachment, html_credential_form |
| filename | Agreement-7589.html | Flagged attachment name |

## Ticket note (copy-ready)

```text
PHISHING TRIAGE - LIKELY PHISHING (risk 100/100)
Subject: Completed: please review and sign
From: "DocuSign" <dse[@]docusgn-mail[.]test>
Sent: 2026-03-07 12:30:00Z | Origin IP: 203[.]0[.]113[.]213
Authentication: SPF fail | DKIM none | DMARC fail
Why it was flagged:
  1. HTML attachment contains a password form (+35) - HTML attachment contains a password field posting to collect[.]docusgn-mail[.]test
  2. Sender domain imitates a protected brand or our own domain (+30) - From domain docusgn-mail[.]test imitates DocuSign (typo of the brand name inside the domain)
  3. DMARC failed for the From domain (+20) - DMARC fail for docusgn-mail[.]test (Authentication-Results)
  4. Display name uses a brand name but the sender domain is not that brand's (+15) - Display name uses 'DocuSign' but the sender domain is docusgn-mail[.]test
  5. SPF failed: the sending server is not authorised for the envelope domain (+15) - SPF result 'fail' for docusgn-mail[.]test (Authentication-Results)
Attachments: Agreement-7589.html (sha256 5ed86dc5629c0b6b...) [FLAGGED]
ATT&CK: T1566.001, T1598.003, T1684.001, T1684.002
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
