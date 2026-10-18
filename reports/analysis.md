# Phishing analysis summary

Source: `data/synthetic/eml` | messages: 36 | benign 15 | suspicious 4 | likely phishing 17 | IOCs 101

> All messages are SYNTHETIC test data.

| Message | Score | Verdict | Subject | Top indicators |
|---|---|---|---|---|
| H06-parcel-fee-decimal-ip | 100 | LIKELY PHISHING | Parcel on hold: pay customs fee | display_name_brand_spoof, dmarc_fail, url_ip_host |
| P01-paypal-lookalike-credential | 100 | LIKELY PHISHING | Action required: unusual sign-in detected | sender_domain_lookalike, url_text_mismatch, dmarc_fail |
| P02-microsoft-idn-homograph | 100 | LIKELY PHISHING | Your mailbox is full - verify your account | display_name_brand_spoof, url_idn_homograph, dmarc_fail |
| P03-docusign-html-credential-attachment | 100 | LIKELY PHISHING | Completed: please review and sign | html_credential_form, sender_domain_lookalike, dmarc_fail |
| P05-invoice-double-extension-exe | 100 | LIKELY PHISHING | Invoice 8841 | attachment_known_bad, attachment_executable, dmarc_fail |
| P08-encrypted-zip-exe-password | 100 | LIKELY PHISHING | Subpoena documents - password inside | archive_contains_executable, archive_encrypted, dmarc_fail |
| P10-cfo-vendor-bank-change-lookalike | 100 | LIKELY PHISHING | Urgent wire transfer - new bank details | sender_domain_lookalike, bec_wording, dmarc_fail |
| P12-mfa-qr-code-phish | 100 | LIKELY PHISHING | Action required: re-validate your account with MFA | display_name_brand_spoof, dmarc_fail, qr_lure |
| P13-amazon-userinfo-ip-url | 100 | LIKELY PHISHING | Problem with your order | sender_domain_lookalike, url_text_mismatch, url_userinfo |
| P14-netflix-open-redirect-billing | 100 | LIKELY PHISHING | Payment failed - update your payment details | display_name_brand_spoof, dmarc_fail, spf_fail |
| P04-remittance-html-smuggling | 97 | LIKELY PHISHING | Remittance advice - open attachment | html_smuggling, dmarc_fail, spf_fail |
| P11-helpdesk-password-reset-spoof | 87 | LIKELY PHISHING | Password expires in 24 hours - keep your current password | sender_domain_lookalike, display_name_exec_spoof, credential_lure |
| P09-ceo-gift-card-bec | 85 | LIKELY PHISHING | Quick favour | gift_card_scam, display_name_exec_spoof, bec_wording |
| H04-payroll-direct-deposit-change | 75 | LIKELY PHISHING | Update your direct deposit before Friday payroll | display_name_exec_spoof, reply_to_mismatch, payment_lure |
| H05-voicemail-svg-script | 65 | LIKELY PHISHING | New voice message (0:42) | svg_script, dmarc_fail, spf_fail |
| P07-scans-zip-with-scr | 63 | LIKELY PHISHING | Scanned documents | archive_contains_executable, dmarc_fail, spf_softfail |
| P06-purchase-order-macro-docm | 60 | LIKELY PHISHING | Purchase order PO-2291 - enable content | attachment_macro, enable_content_lure, payment_lure |
| B12-secops-awareness-quoted-phish | 28 | SUSPICIOUS | Awareness: spot this week's fake PayPal email | credential_lure, url_brand_in_domain, url_login_keywords |
| S01-partner-encrypted-zip | 28 | SUSPICIOUS | Shipping documents for PO 4471 | archive_encrypted, archive_password_hint |
| S03-unknown-vendor-invoice-reply-to | 28 | SUSPICIOUS | Invoice 55120 overdue | reply_to_mismatch, payment_lure, auth_absent |
| S02-shared-doc-unauth-shortlink | 25 | SUSPICIOUS | Sam shared a document with you | credential_lure, url_shortener, auth_absent |
| H07-unauth-rar-password | 18 | BENIGN | Requested records | archive_password_hint, auth_absent |
| B04-saas-password-reset | 8 | BENIGN | Reset your Cloudnote password | credential_lure, urgency_language |
| B08-event-ticket-qr | 3 | BENIGN | Your ticket for Saturday | qr_lure |
| B01-newsletter-harbour-gazette | 0 | BENIGN | This week: harbour dredging, new ferry timetable | - |
| B02-internal-finance-approvals | 0 | BENIGN | Q3 invoice approvals - sign-off needed Friday | - |
| B03-hr-benefits-deadline | 0 | BENIGN | URGENT: benefits enrolment closes in 3 days - action require | urgency_language |
| B05-shop-order-receipt | 0 | BENIGN | Your order #LB-20931 - receipt attached | payment_lure |
| B06-monitoring-alert-no-msgid | 0 | BENIGN | [ALERT] disk usage 91% on db-02 | message_id_missing |
| B07-events-idn-muenchen | 0 | BENIGN | Your concert tickets | - |
| B09-courier-parcel-shortlink | 0 | BENIGN | Your parcel arrives today | url_shortener |
| B10-mailing-list-digest | 0 | BENIGN | [nettalk] re: switch firmware 4.2 rollout | - |
| H01-saas-billing-receipt-esp | 0 | BENIGN | Your Brightline invoice for March is ready | payment_lure |
| H02-newsletter-unicode-cafe | 0 | BENIGN | Menu για την εβδομάδα - weekly specials | generic_greeting |
| H03-internal-maintenance-notice | 0 | BENIGN | Scheduled maintenance Saturday 22:00-23:00 | - |
| H08-aws-billing-brand-on-real-domain | 0 | BENIGN | Your AWS invoice is available | - |
