#!/usr/bin/env python3
"""Flask web application for Safeguard Pro+ (AI security toolkit).

Run:
    python app.py
then open http://127.0.0.1:5000

Pages
-----
GET  /                      HTML dashboard
GET  /network/              Network & host vulnerability assessment (mounted)

Phishing API
------------
POST /api/analyze-url       JSON { url } -> full report
POST /api/analyze-email     JSON { raw_email | subject | body } -> full report
GET  /api/health            model + module status
GET  /api/examples          built-in demo samples

Toolkit API
-----------
POST /api/password/check    JSON { password } -> strength audit
POST /api/password/generate JSON { length, upper, lower, digits, symbols, mode }
POST /api/crypto/hash       JSON { text, algorithms[] }
POST /api/crypto/encode     JSON { text, method, decode }
POST /api/crypto/cipher     JSON { text, cipher, key, decrypt }
POST /api/crypto/hmac       JSON { message, key, algorithm }
POST /api/file/analyze      multipart file=@…  OR JSON { text | base64, filename }
POST /api/log/analyze       JSON { log }
"""

from __future__ import annotations

import base64
import os

from flask import Flask, jsonify, render_template, request
from werkzeug.middleware.dispatcher import DispatcherMiddleware

from phishing_detector import __version__
from phishing_detector.crypto_tool import (
    CLASSICAL_CIPHERS,
    HASH_ALGORITHMS,
    encode_text,
    hash_text,
    hmac_sign,
    classical_cipher,
)
from phishing_detector.explainer import build_email_report, build_url_report
from phishing_detector.file_analyzer import analyze_bytes, analyze_text
from phishing_detector.log_monitor import analyze_log
from phishing_detector.model import ModelStore
from phishing_detector.password_tool import (
    check_password,
    generate_passphrase,
    generate_password,
    generate_pin,
)

MAX_PAYLOAD_BYTES = 8 * 1024 * 1024  # 8 MB (file triage + pasted logs)
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_PAYLOAD_BYTES

#: Models live next to this file in ``models/``.
STORE = ModelStore(os.path.join(os.path.dirname(os.path.abspath(__file__)), "models"))

#: Network assessment is mounted at /network so one Safeguard Pro+ deployment
#: exposes every defensive tool on a single port.
from network_app.scanner import __version__ as NETWORK_VERSION  # noqa: E402
from network_app.webapp import app as network_app  # noqa: E402

app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {"/network": network_app})


# --------------------------------------------------------------------------
# Serialisation helpers
# --------------------------------------------------------------------------

def _finding(finding) -> dict:
    return {
        "code": finding.code,
        "title": finding.title,
        "detail": finding.detail,
        "severity": finding.severity,
        "points": finding.points,
    }


def _report_payload(report) -> dict:
    return {
        "kind": report.kind,
        "target": report.target,
        "verdict": report.verdict,
        "verdict_label": report.verdict_label,
        "risk_class": report.risk_class,
        "probability": round(report.probability, 4),
        "ml_probability": round(report.ml_probability, 4),
        "rule_score": report.rule_score,
        "summary": report.summary,
        "warnings": [_finding(f) for f in report.warnings],
        "trust": [_finding(f) for f in report.trust],
        "ml_signs": report.ml_signs,
        "trust_signs": report.trust_signs,
        "meta": report.meta,
    }


def _tool_payload(report) -> dict:
    """Uniform JSON for the toolkit modules (password/crypto/file/log)."""
    return {
        "kind": report.kind,
        "title": report.title,
        "risk": report.risk,
        "risk_class": report.risk_class,
        "score": report.score,
        "grade": report.grade,
        "summary": report.summary,
        "findings": [_finding(f) for f in report.sorted_findings()],
        "details": [{"label": label, "value": value} for label, value in report.details],
        "advice": report.advice,
        "meta": report.meta,
    }


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

@app.get("/")
def index():
    return render_template("index.html")


@app.get("/robots.txt")
def robots():
    """Crawl directives; API routes are excluded from indexing."""
    from flask import Response
    body = ("User-agent: *\n"
            "Allow: /\n"
            "Disallow: /api/\n"
            "Disallow: /network/api/\n\n"
            "Sitemap: {base}/sitemap.xml\n")
    return Response(body.format(base=request.host_url.rstrip("/")),
                    mimetype="text/plain")


@app.get("/sitemap.xml")
def sitemap():
    """Single-page sitemap for search engines."""
    from flask import Response
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
           '  <url>\n'
           f'    <loc>{request.host_url}</loc>\n'
           '    <changefreq>monthly</changefreq>\n'
           '    <priority>1.0</priority>\n'
           '  </url>\n'
           '  <url>\n'
           f'    <loc>{request.host_url}network/</loc>\n'
           '    <changefreq>monthly</changefreq>\n'
           '    <priority>0.9</priority>\n'
           '  </url>\n'
           '</urlset>\n')
    return Response(xml, mimetype="application/xml")


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------

@app.get("/api/health")
def health():
    status = STORE.status()
    status["ok"] = True
    status["version"] = __version__
    status["modules"] = ["phishing", "password", "crypto", "file", "log", "network"]
    status["network"] = {
        "ok": True,
        "version": NETWORK_VERSION,
        "url": "/network/",
        "mode": "non-exploitative TCP connect",
    }
    return jsonify(status)


@app.get("/api/examples")
def examples():
    """Built-in demo samples so the UI is usable without real data."""
    return jsonify({
        "url_phishing": "http://paypal.com@secure-login-verify.tk/account/verify"
                        "?session=8831&email=user%40mail.com",
        "url_shortener": "https://bit.ly/3xYzAbC",
        "url_legit": "https://docs.python.org/3/library/email.html",
        "email_phishing": (
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
            "</body></html>\n"
        ),
        "email_legit": (
            "Return-Path: <notifications@github.com>\n"
            "From: \"GitHub\" <notifications@github.com>\n"
            "Subject: [myorg/repo] Pull request #42 merged\n"
            "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n"
            "Message-ID: <abc123@github.com>\n"
            "Received: from github.com (github.com [140.82.112.3]) by mx.example;\n"
            "\n"
            "Hi Alex,\n\nThe pull request has been merged into main. "
            "Tests are green. See https://github.com/myorg/repo/pull/42 for details.\n\n"
            "-- GitHub\n"
        ),
        "password_weak": "Summer2024!",
        "password_strong": "vT7$qLm2#Wz9!Rx4",
        "log_attack": (
            '203.0.113.45 - - [12/Oct/2026:03:14:07 +0000] "GET /index.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 512 "-" "sqlmap/1.7"\n'
            '203.0.113.45 - - [12/Oct/2026:03:14:09 +0000] "GET /.env HTTP/1.1" 404 196 "-" "sqlmap/1.7"\n'
            '203.0.113.45 - - [12/Oct/2026:03:14:11 +0000] "GET /../../etc/passwd HTTP/1.1" 403 220 "-" "sqlmap/1.7"\n'
            '203.0.113.45 - - [12/Oct/2026:03:14:14 +0000] "GET /admin.php?cmd=;cat%20/etc/shadow HTTP/1.1" 500 512 "-" "sqlmap/1.7"\n'
            '198.51.100.9 - - [12/Oct/2026:03:15:02 +0000] "GET / HTTP/1.1" 200 1043 "-" "Mozilla/5.0"\n'
            "Oct 12 03:20:11 kali sshd[2210]: Failed password for root from 198.51.100.77 port 51022 ssh2\n"
            "Oct 12 03:20:14 kali sshd[2211]: Failed password for admin from 198.51.100.77 port 51024 ssh2\n"
            "Oct 12 03:20:17 kali sshd[2212]: Failed password for invalid user oracle from 198.51.100.77 port 51026 ssh2\n"
            "Oct 12 03:20:21 kali sshd[2213]: Failed password for root from 198.51.100.77 port 51028 ssh2\n"
            "Oct 12 03:20:24 kali sshd[2214]: Failed password for root from 198.51.100.77 port 51030 ssh2\n"
            "Oct 12 03:20:29 kali sshd[2215]: Failed password for root from 198.51.100.77 port 51032 ssh2\n"
        ),
    })


@app.post("/api/analyze-url")
def analyze_url_endpoint():
    payload = request.get_json(silent=True) or {}
    target = (payload.get("url") or "").strip()
    if not target:
        return jsonify({"error": "Provide a 'url' field."}), 400
    if len(target) > 8000:
        return jsonify({"error": "URL too long (max 8000 characters)."}), 400

    STORE.ensure()
    try:
        report = build_url_report(target, STORE.url_model)
    except Exception as exc:  # pragma: no cover - defensive
        return jsonify({"error": f"Analysis failed: {exc}"}), 500
    return jsonify(_report_payload(report))


@app.post("/api/analyze-email")
def analyze_email_endpoint():
    payload = request.get_json(silent=True) or {}
    raw = payload.get("raw_email") or payload.get("email") or ""
    subject = payload.get("subject") or ""
    body = payload.get("body") or ""

    if not (raw.strip() or subject.strip() or body.strip()):
        return jsonify({"error": "Provide 'raw_email' or 'subject'/'body'."}), 400

    STORE.ensure()
    try:
        report = build_email_report(raw_email=raw, subject=subject, body=body,
                                    model=STORE.email_model)
    except Exception as exc:  # pragma: no cover - defensive
        return jsonify({"error": f"Analysis failed: {exc}"}), 500
    return jsonify(_report_payload(report))


# --------------------------------------------------------------------------
# Toolkit API
# --------------------------------------------------------------------------

def _error(message: str, code: int = 400):
    return jsonify({"error": message}), code


@app.post("/api/password/check")
def password_check():
    payload = request.get_json(silent=True) or {}
    password = payload.get("password")
    if password is None:
        return _error("Provide a 'password' field.")
    if not isinstance(password, str):
        return _error("'password' must be a string.")
    if len(password) > 1024:
        return _error("Password too long (max 1024 characters).")
    return jsonify(_tool_payload(check_password(password)))


@app.post("/api/password/generate")
def password_generate():
    payload = request.get_json(silent=True) or {}
    mode = (payload.get("mode") or "password").lower()

    if mode == "passphrase":
        value = generate_passphrase(
            words=int(payload.get("words") or 4),
            separator=str(payload.get("separator") or "-"),
            capitalize=bool(payload.get("capitalize", True)),
            add_digits=bool(payload.get("add_digits", True)),
        )
        label = "Passphrase"
    elif mode == "pin":
        value = generate_pin(int(payload.get("length") or 6))
        label = "PIN"
    else:
        value = generate_password(
            length=int(payload.get("length") or 16),
            upper=bool(payload.get("upper", True)),
            lower=bool(payload.get("lower", True)),
            digits=bool(payload.get("digits", True)),
            symbols=bool(payload.get("symbols", True)),
            avoid_ambiguous=bool(payload.get("avoid_ambiguous", True)),
        )
        label = "Password"

    report = check_password(value)
    data = _tool_payload(report)
    data["title"] = f"Generated {label.lower()}"
    data["generated"] = value
    data["generated_label"] = label
    return jsonify(data)


@app.post("/api/crypto/hash")
def crypto_hash():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text")
    if not isinstance(text, str):
        return _error("Provide a 'text' field.")
    algorithms = payload.get("algorithms") or list(HASH_ALGORITHMS)
    if not isinstance(algorithms, list):
        algorithms = list(HASH_ALGORITHMS)
    return jsonify(_tool_payload(hash_text(text, tuple(algorithms))))


@app.post("/api/crypto/encode")
def crypto_encode():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text")
    if not isinstance(text, str):
        return _error("Provide a 'text' field.")
    return jsonify(_tool_payload(
        encode_text(text,
                    method=str(payload.get("method") or "base64"),
                    decode=bool(payload.get("decode", False)),
    )))


@app.post("/api/crypto/cipher")
def crypto_cipher():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text")
    if not isinstance(text, str):
        return _error("Provide a 'text' field.")
    cipher = str(payload.get("cipher") or "caesar")
    if cipher not in CLASSICAL_CIPHERS:
        return _error(f"Unknown cipher. Choose one of: {', '.join(CLASSICAL_CIPHERS)}.")
    return jsonify(_tool_payload(
        classical_cipher(text,
                         cipher=cipher,
                         key=str(payload.get("key") or ""),
                         decrypt=bool(payload.get("decrypt", False)),
    )))


@app.post("/api/crypto/hmac")
def crypto_hmac():
    payload = request.get_json(silent=True) or {}
    message = payload.get("message")
    if not isinstance(message, str):
        return _error("Provide a 'message' field.")
    return jsonify(_tool_payload(
        hmac_sign(message,
                  key=str(payload.get("key") or ""),
                  algorithm=str(payload.get("algorithm") or "sha256"),
    )))


@app.post("/api/file/analyze")
def file_analyze():
    """Analyse an uploaded file, pasted text, or base64 payload."""
    upload = request.files.get("file")
    if upload is not None and upload.filename:
        data = upload.read(MAX_PAYLOAD_BYTES + 1)
        if len(data) > MAX_PAYLOAD_BYTES:
            return _error(f"File too large (max {MAX_PAYLOAD_BYTES // (1024 * 1024)} MB).", 413)
        return jsonify(_tool_payload(analyze_bytes(data, upload.filename)))

    payload = request.get_json(silent=True) or {}
    filename = str(payload.get("filename") or "pasted.txt")

    if payload.get("base64"):
        try:
            data = base64.b64decode(payload["base64"], validate=False)
        except (ValueError, TypeError):
            return _error("Invalid base64 payload.")
        return jsonify(_tool_payload(analyze_bytes(data, filename)))

    text = payload.get("text")
    if isinstance(text, str) and text:
        return jsonify(_tool_payload(analyze_text(text, filename)))

    return _error("Upload a file, or provide 'text' or 'base64'.")


@app.post("/api/log/analyze")
def log_analyze():
    payload = request.get_json(silent=True) or {}
    log = payload.get("log")
    if not isinstance(log, str):
        return _error("Provide a 'log' field containing the log text.")
    if len(log) > MAX_PAYLOAD_BYTES:
        return _error("Log too large (max 8 MB).", 413)
    return jsonify(_tool_payload(analyze_log(log)))


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Payload too large (max 8 MB)."}), 413


if __name__ == "__main__":
    # Warm the models up on first launch so the first request is fast.
    try:
        STORE.ensure()
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[warn] could not load/train models: {exc}")

    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes", "on"}
    print(f"Safeguard Pro+ starting on http://127.0.0.1:{port}")
    print(f"Network assessment: http://127.0.0.1:{port}/network/")
    app.run(host="127.0.0.1", port=port, debug=debug)
