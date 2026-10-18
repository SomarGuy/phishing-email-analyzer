> **SYNTHETIC SAMPLE.** This message was written for testing; the people, organisations, domains and IPs are fictional or reserved.

# Incident report: Problem with your order

| Field | Value |
|---|---|
| Verdict | **LIKELY PHISHING** (risk score 100/100) |
| Message | P13-amazon-userinfo-ip-url |
| From | "Amazon Orders" <orders[@]amaz0n-delivery[.]test> |
| Reply-To / Return-Path | (none) / <orders[@]amaz0n-delivery[.]test> |
| Date / origin IP | 2026-03-17 11:11:00Z / 203[.]0[.]113[.]19 |
| Authentication | SPF fail \| DKIM none \| DMARC fail |
| ATT&CK | T1684.001 Social Engineering: Impersonation, T1566.002 Phishing: Spearphishing Link, T1204.001 User Execution: Malicious Link, T1684.002 Social Engineering: Email Spoofing, T1598.003 Phishing for Information: Spearphishing Link |

## Why

| Pts | Sev | Indicator | Detail |
|---|---|---|---|
| +30 | high | Sender domain imitates a protected brand or our own domain | From domain amaz0n-delivery[.]test imitates Amazon (brand name inside the domain) |
| +25 | high | Link text shows one address but the link goes to another | Link text shows www.amazon.com but the link goes to 0xcb007150 |
| +25 | high | Link contains user@ credentials syntax that hides the real host | URL has credentials-style prefix 'www.amazon.com@' before the real host 0xcb007150 |
| +20 | high | DMARC failed for the From domain | DMARC fail for amaz0n-delivery[.]test (Authentication-Results) |
| +15 | high | Display name uses a brand name but the sender domain is not that brand's | Display name uses 'Amazon' but the sender domain is amaz0n-delivery[.]test |
| +15 | high | SPF failed: the sending server is not authorised for the envelope domain | SPF result 'fail' for amaz0n-delivery[.]test (Authentication-Results) |
| +12 | medium | Asks the reader to verify, confirm or reset credentials | Credential-harvesting wording: 'Update your payment details' |
| +10 | high | Link points to a raw IP address | Host is the IP address 203.0.113.80 written as '0xcb007150' |

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
| email | orders[@]amaz0n-delivery[.]test | From address |
| domain | amaz0n-delivery[.]test | Sender domain |
| ip | 203[.]0[.]113[.]19 | Origin of the Received chain |
| url | hxxp://www[.]amazon[.]com@0xCB007150/orders/fix | url_ip_host; url_obfuscated; url_userinfo |

## Ticket note (copy-ready)

```text
PHISHING TRIAGE - LIKELY PHISHING (risk 100/100)
Subject: Problem with your order
From: "Amazon Orders" <orders[@]amaz0n-delivery[.]test>
Sent: 2026-03-17 11:11:00Z | Origin IP: 203[.]0[.]113[.]19
Authentication: SPF fail | DKIM none | DMARC fail
Why it was flagged:
  1. Sender domain imitates a protected brand or our own domain (+30) - From domain amaz0n-delivery[.]test imitates Amazon (brand name inside the domain)
  2. Link text shows one address but the link goes to another (+25) - Link text shows www.amazon.com but the link goes to 0xcb007150
  3. Link contains user@ credentials syntax that hides the real host (+25) - URL has credentials-style prefix 'www.amazon.com@' before the real host 0xcb007150
  4. DMARC failed for the From domain (+20) - DMARC fail for amaz0n-delivery[.]test (Authentication-Results)
  5. Display name uses a brand name but the sender domain is not that brand's (+15) - Display name uses 'Amazon' but the sender domain is amaz0n-delivery[.]test
Suspicious links: hxxp://www[.]amazon[.]com@0xCB007150/orders/fix
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
