#!/usr/bin/env python3
"""Command-line interface for Safeguard Pro+.

Examples
--------
    python cli.py url https://paypal.com@secure-login-verify.tk/account
    python cli.py url suspicious.txt
    python cli.py email email.txt
    python cli.py email --subject "Verify now" --body "Click https://x.tk/login"
    python cli.py password "Summer2024!"
    python cli.py password --generate 20
    python cli.py hash "hello world"
    python cli.py hash --file setup.exe
    python cli.py encode "hello" --method base64
    python cli.py file suspicious.pdf.exe
    python cli.py log /var/log/nginx/access.log
    python cli.py demo
"""

from __future__ import annotations

import argparse
import os
import sys

from phishing_detector.crypto_tool import encode_text, hash_file, hash_text
from phishing_detector.explainer import build_email_report, build_url_report
from phishing_detector.file_analyzer import analyze_file
from phishing_detector.log_monitor import analyze_log
from phishing_detector.model import ModelStore
from phishing_detector.password_tool import (
    check_password,
    generate_passphrase,
    generate_password,
    generate_pin,
)

# Pretty console colours (disabled when not a TTY / on Windows without ANSI)
_COLORS = {
    "danger": "\033[91m",
    "warning": "\033[93m",
    "safe": "\033[92m",
    "dim": "\033[90m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}

SEVERITY_MARK = {"high": "!!", "medium": " !", "low": "  "}


def _configure_console() -> None:
    """Make stdout UTF-8 so box/bar glyphs never crash a legacy console.

    Windows terminals default to a code page (e.g. cp1252) that cannot encode
    the progress-bar characters; switching the stream to UTF-8 with a safe
    fallback keeps output portable.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):  # pragma: no cover
            pass


def _c(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['reset']}"


def render_report(report) -> str:
    lines: list[str] = []
    bar_len = 30
    filled = int(round(report.probability * bar_len))
    bar = "#" * filled + "-" * (bar_len - filled)

    lines.append("")
    lines.append(_c("=" * 66, "dim"))
    lines.append(f"{_c('VERDICT', 'bold')}: "
                 f"{_c(report.verdict_label.upper(), report.risk_class)}")
    lines.append(f"Phishing probability: [{bar}] {report.probability * 100:5.1f}%")
    lines.append(f"  ML model: {report.ml_probability * 100:5.1f}%   "
                 f"Rule score: {report.rule_score}/100")
    lines.append(_c("=" * 66, "dim"))

    lines.append("\nWHY — main reasons")
    if report.summary:
        for item in report.summary:
            lines.append(f"  * {item}")

    if report.warnings:
        lines.append("\nWARNING SIGNS")
        ordered = sorted(report.warnings, key=lambda f: {"high": 0, "medium": 1, "low": 2}[f.severity])
        for f in ordered:
            mark = SEVERITY_MARK.get(f.severity, " ")
            color = {"high": "danger", "medium": "warning", "low": "dim"}[f.severity]
            lines.append(f"  {_c('[' + f.severity.upper() + ']', color)} {f.title}")
            lines.append(f"        {_c(f.detail, 'dim')}")

    if report.ml_signs:
        lines.append("\nWHAT THE MODEL NOTICED")
        for sign in report.ml_signs:
            lines.append(f"  + {sign}")

    if report.trust_signs:
        lines.append("\nEVIDENCE OF LEGITIMACY")
        for sign in report.trust_signs:
            lines.append(f"  - {sign}")

    lines.append("\nRECOMMENDATION")
    if report.verdict == "phishing":
        lines.append(_c("  Do NOT click, reply or enter any credentials. "
                        "Report and delete the message.", "danger"))
    elif report.verdict == "suspicious":
        lines.append(_c("  Treat as untrusted. Verify the sender through an "
                        "official channel you already know.", "warning"))
    else:
        lines.append(_c("  No strong indicators found — still verify before "
                        "sharing sensitive data.", "safe"))

    if report.kind == "email" and report.meta:
        lines.append(_c("\nHEADER SUMMARY", "dim"))
        meta = report.meta
        lines.append(f"  From        : {meta.get('sender_name', '')} <{meta.get('sender_addr', '')}>")
        for key in ("return_path", "reply_to"):
            if meta.get(key):
                lines.append(f"  {key.replace('_', ' ').title():<12}: {meta[key]}")
        lines.append(f"  SPF/DKIM/DMARC: {meta.get('spf')} / {meta.get('dkim')} / {meta.get('dmarc')}")
        if meta.get("links"):
            lines.append(f"  Links found : {len(meta['links'])}")
        if meta.get("attachments"):
            lines.append(f"  Attachments : {', '.join(meta['attachments'])}")

    lines.append("")
    return "\n".join(lines)


def render_tool(report) -> str:
    """Render a :class:`ToolReport` (password / crypto / file / log) for the console."""
    lines: list[str] = []
    risk_color = {"danger": "danger", "warning": "warning", "safe": "safe"}.get(
        report.risk_class, "dim")
    label = report.grade or report.risk.replace("_", " ").title()

    lines.append("")
    lines.append(_c("=" * 66, "dim"))
    lines.append(f"{_c(report.kind.upper(), 'dim')}  {report.title}")
    lines.append(f"{_c('RESULT', 'bold')}: {_c(label.upper(), risk_color)}")

    if isinstance(report.score, (int, float)):
        bar_len = 30
        filled = int(round(max(0, min(100, report.score)) / 100 * bar_len))
        bar = "#" * filled + "-" * (bar_len - filled)
        lines.append(f"Score: [{bar}] {report.score}/100")
    lines.append(_c("=" * 66, "dim"))

    generated = getattr(report, "generated", None)
    if generated:
        lines.append("")
        lines.append(_c("GENERATED SECRET", "bold"))
        lines.append(f"  {_c(generated, 'safe')}")

    if report.summary:
        lines.append("\nSUMMARY")
        for item in report.summary:
            lines.append(f"  * {item}")

    if report.findings:
        lines.append("\nFINDINGS")
        for f in report.sorted_findings():
            color = {"critical": "danger", "high": "danger",
                     "medium": "warning"}.get(f.severity, "dim")
            lines.append(f"  {_c('[' + f.severity.upper() + ']', color)} {f.title}")
            if f.detail:
                lines.append(f"        {_c(f.detail, 'dim')}")

    if report.details:
        lines.append("\nDETAILS")
        width = max(len(str(label)) for label, _ in report.details)
        for label, value in report.details:
            lines.append(f"  {str(label).ljust(width)} : {value}")

    if report.advice:
        lines.append("\nRECOMMENDATIONS")
        for item in report.advice:
            lines.append(f"  - {item}")

    lines.append("")
    return "\n".join(lines)


def _read_source(value: str) -> str:
    """Return file contents when *value* is an existing path, else the value."""
    if os.path.isfile(value):
        with open(value, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return value


def main(argv: list[str] | None = None) -> int:
    _configure_console()
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="Safeguard Pro+ — defensive security toolkit: phishing, "
                    "passwords, cryptography, file triage and log monitoring.")
    sub = parser.add_subparsers(dest="command", required=True)

    url_p = sub.add_parser("url", help="analyse a URL (or a file of URLs)")
    url_p.add_argument("target", help="URL string, or path to a file with one URL per line")
    url_p.add_argument("--threshold", type=float, default=None,
                       help="override phishing probability threshold (0-1)")

    email_p = sub.add_parser("email", help="analyse a raw email (or subject/body)")
    email_p.add_argument("target", nargs="?", default="",
                         help="raw email text or path to a .eml/.txt file")
    email_p.add_argument("--subject", default="")
    email_p.add_argument("--body", default="")

    pw_p = sub.add_parser("password", help="audit or generate a password")
    pw_p.add_argument("value", nargs="?", default="", help="password to audit")
    pw_p.add_argument("--generate", type=int, metavar="LENGTH", default=None,
                      help="generate a random password of LENGTH characters")
    pw_p.add_argument("--mode", choices=["password", "passphrase", "pin"],
                      default="password", help="generator mode (default: password)")

    hash_p = sub.add_parser("hash", help="hash text or a file")
    hash_p.add_argument("target", help="text, or a file path when --file is used")
    hash_p.add_argument("--file", action="store_true", help="treat target as a file path")

    enc_p = sub.add_parser("encode", help="encode or decode text")
    enc_p.add_argument("target", help="text to encode/decode (or a file path)")
    enc_p.add_argument("--method", default="base64",
                       choices=["base64", "base32", "base16", "base85",
                                "url", "html", "binary"])
    enc_p.add_argument("--decode", action="store_true", help="decode instead of encode")

    file_p = sub.add_parser("file", help="static malware triage of a file")
    file_p.add_argument("path", help="file to analyse (never executed)")

    log_p = sub.add_parser("log", help="scan access/auth logs for attacks")
    log_p.add_argument("path", help="log file to analyse")

    sub.add_parser("demo", help="run built-in example samples")
    sub.add_parser("status", help="show model file status")

    args = parser.parse_args(argv)

    # ---- model-free tools -------------------------------------------------
    if args.command == "password":
        if args.generate:
            if args.mode == "passphrase":
                generated = generate_passphrase(words=max(3, args.generate // 4))
            elif args.mode == "pin":
                generated = generate_pin(args.generate)
            else:
                generated = generate_password(length=args.generate)
            report = check_password(generated)
            report.generated = generated  # extra field used by render_tool
            print(render_tool(report))
            return 0
        if not args.value:
            parser.error("provide a password to audit, or use --generate LENGTH")
        print(render_tool(check_password(args.value)))
        return 0

    if args.command == "hash":
        if args.file:
            print(render_tool(hash_file(args.target)))
        else:
            print(render_tool(hash_text(_read_source(args.target))))
        return 0

    if args.command == "encode":
        print(render_tool(encode_text(_read_source(args.target),
                                     method=args.method, decode=args.decode)))
        return 0

    if args.command == "file":
        if not os.path.isfile(args.path):
            parser.error(f"file not found: {args.path}")
        print(render_tool(analyze_file(args.path)))
        return 0

    if args.command == "log":
        if not os.path.isfile(args.path):
            parser.error(f"log file not found: {args.path}")
        print(render_tool(analyze_log(_read_source(args.path))))
        return 0

    # ---- phishing engine (needs trained models) ---------------------------
    store = ModelStore("models")

    if args.command == "status":
        print(store.status())
        return 0

    if args.command == "demo":
        _demo(store)
        return 0

    store.ensure()

    if args.command == "url":
        source = _read_source(args.target)
        targets = [t.strip() for t in source.splitlines() if t.strip()] if os.path.isfile(args.target) else [args.target]
        for target in targets:
            report = build_url_report(target, store.url_model)
            if args.threshold is not None:
                from phishing_detector.explainer import verdict_for
                report.verdict, report.verdict_label = verdict_for(args.threshold)
            print(render_report(report))
        return 0

    raw = _read_source(args.target) if args.target else ""
    body = _read_source(args.body) if args.body else ""
    report = build_email_report(raw_email=raw, subject=args.subject, body=body, model=store.email_model)
    print(render_report(report))
    return 0


def _demo(store: ModelStore) -> None:
    store.ensure()
    print(_c("\n### DEMO 1 — credential-stealing URL", "bold"))
    print(render_report(build_url_report(
        "http://paypal.com@secure-login-verify.tk/account/verify?session=8831&email=a%40b.com",
        store.url_model)))

    print(_c("\n### DEMO 2 — legitimate URL", "bold"))
    print(render_report(build_url_report("https://docs.python.org/3/library/email.html",
                                        store.url_model)))

    print(_c("\n### DEMO 3 — spoofed delivery email", "bold"))
    demo_email = (
        "Return-Path: <bounce@mail-random-host.xyz>\n"
        "From: \"DHL Express\" <delivery@mail-random-host.xyz>\n"
        "Reply-To: recover@another-host.tk\n"
        "Subject: Urgent: your package is on hold - confirm your address immediately\n"
        "Authentication-Results: mx.example; spf=fail; dkim=none; dmarc=fail\n"
        "Message-ID: <20260101@mail-random-host.xyz>\n"
        "Content-Type: text/html; charset=utf-8\n"
        "\n"
        "<html><body><p>Dear customer, your parcel could not be delivered. "
        "Confirm your address and pay the redelivery fee within 24 hours.</p>"
        "<p><a href=\"http://track-dhl-secure.xyz/track?id=7788\">dhl.com/tracking</a></p>"
        "<form action=\"http://track-dhl-secure.xyz/collect\"><input name=\"card\"></form>"
        "</body></html>\n"
    )
    print(render_report(build_email_report(raw_email=demo_email, model=store.email_model)))


if __name__ == "__main__":
    sys.exit(main())
