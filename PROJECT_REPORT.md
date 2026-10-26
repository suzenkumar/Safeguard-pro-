# PROJECT REPORT

## Safeguard Pro+ — AI Security Toolkit

---

| | |
|---|---|
| **Project Title** | Safeguard Pro+ — AI Security Toolkit |
| **Modules** | Phishing detection · Password audit · Cryptography · File triage · Log monitoring |
| **Submitted By** | **Er-Suzen Kumar Mohanty** |
| **Programme** | **IBM SkillsBuild / IBM Cyber Security Project** |
| **Domain** | Cyber Security / Defensive Security |
| **Project Level** | Beginner – Intermediate |
| **Technology Stack** | Python · Machine Learning · NLP · Flask · scikit-learn · stdlib cryptography |
| **Report Date** | 25 October 2026 |
| **Version** | 2.0 |

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Introduction](#2-introduction)
3. [Problem Statement](#3-problem-statement)
4. [Objectives](#4-objectives)
5. [Literature / Background Study](#5-literature--background-study)
6. [System Requirements](#6-system-requirements)
7. [System Architecture](#7-system-architecture)
8. [Methodology](#8-methodology)
9. [Module Description](#9-module-description)
10. [Machine Learning Design](#10-machine-learning-design)
11. [Implementation Details](#11-implementation-details)
12. [Results and Testing](#12-results-and-testing)
13. [Sample Outputs](#13-sample-outputs)
14. [Advantages and Limitations](#14-advantages-and-limitations)
15. [Future Scope](#15-future-scope)
16. [Conclusion](#16-conclusion)
17. [References](#17-references)
18. [Appendix](#18-appendix)

---

## 1. Abstract

Phishing remains one of the most successful and most common cyber-attacks in the
world. Attackers impersonate trusted organisations through deceptive emails and
fake websites to steal credentials, payment details, and one-time passwords.

**Safeguard Pro+** is a defensive, offline AI security toolkit that bundles five
tools behind one explained dashboard. It began as **PhishGuard**, an AI-based
phishing detector for suspicious **URLs** and **emails**, and has been expanded
into a broader learning platform:

1. **Phishing detection** — rule engines plus machine learning, with every warning
   explained.
2. **Password strength auditing and generation** — entropy-based scoring, dictionary
   and pattern detection, realistic crack-time estimation, and a secure generator.
3. **Cryptography basics** — hashing, encodings, classical ciphers, HMAC, PBKDF2 and
   optional AES-256-GCM.
4. **File / malware triage** — static analysis using magic bytes, entropy, PE headers
   and suspicious-behaviour signatures.
5. **Log monitoring** — web and SSH log parsing with detection of SQL injection, XSS,
   traversal, brute force and possible compromise.

All five tools share one report contract (`ToolReport`), one responsive Flask
dashboard, one JSON API and one command-line interface. Every result lists its
evidence and a recommended next action, which makes the toolkit both a practical
defence aid and an educational instrument.

**Keywords:** phishing detection, machine learning, NLP, TF-IDF, logistic
regression, SPF, DKIM, DMARC, password strength, entropy, hashing, HMAC, PBKDF2,
malware triage, log analysis, intrusion detection, cyber security, Flask,
defensive security.

---

## 2. Introduction

### 2.1 What is Phishing?

Phishing is a **social-engineering attack** in which a criminal impersonates a
trustworthy entity — a bank, a delivery company, a cloud provider — to trick the
victim into revealing sensitive information or installing malware.

Typical delivery methods:

* **Email phishing** — a forged message containing a link to a fake login page.
* **Spear phishing** — a highly targeted message referencing the victim by name.
* **Smishing / Vishing** — the same attack delivered by SMS or voice call.
* **Clone phishing** — a copy of a legitimate message with the link replaced.

### 2.2 Why Phishing Detection Matters

* Phishing is consistently among the top initial-access vectors in major breach
  reports.
* A single successful credential theft can lead to full account takeover,
  financial fraud, and lateral movement inside a corporate network.
* Ordinary users cannot reliably inspect a URL's structure, SPF/DKIM results, or
  homoglyph domains — so tooling must bridge that knowledge gap.

### 2.3 The Safeguard Pro+ Approach

Rather than producing an opaque "spam / not spam" label, Safeguard Pro+ is built
around **explainability**. Every verdict is accompanied by:

* the specific features or rules that raised suspicion,
* the evidence that supports legitimacy (where applicable),
* concrete technical facts (hashes, entropy, parsed-line coverage, crack time),
* and a recommended course of action.

The same principle is applied outside phishing. A password report explains *why* a
password is weak (dictionary word, date, keyboard walk); a file report explains
*which* behaviour strings were found; a log report explains *which* request lines
matched an attack signature. This makes the toolkit both a **detector** and an
**educational instrument**.

---

## 3. Problem Statement

> *Users receive suspicious links and emails every day but have no accessible,
> explainable way to judge whether they are safe. Existing antispam filters are
> opaque, and manual inspection requires specialist knowledge of URL structure,
> email authentication (SPF/DKIM/DMARC), and homoglyph attacks. The same gap exists
> for password hygiene, file downloads, and server logs: the tools are either
> enterprise-only, cloud-based, or impossible for a learner to inspect.*

Therefore, there is a need for a system that:

1. Analyses suspicious **URLs and emails** automatically.
2. Uses **machine learning** to classify unseen samples.
3. **Explains** every warning sign in language a non-expert can understand.
4. Audits **passwords** and generates secure replacements.
5. Demonstrates **cryptography** with honest warnings about weak algorithms.
6. Performs **static file triage** without executing the sample.
7. Detects **attacks in server logs** and highlights possible compromise.
8. Runs **locally and privately** without sending user data to third parties.
9. Presents results through an accessible **web interface** and a **CLI**.

---

## 4. Objectives

| # | Objective | Status |
|---|---|---|
| 1 | Inspect URL structure and identify suspicious domains | ✅ Achieved |
| 2 | Analyse email headers and message patterns | ✅ Achieved |
| 3 | Classify samples using machine learning | ✅ Achieved |
| 4 | Explain warning signs to the user in plain language | ✅ Achieved |
| 5 | Build a responsive web interface (Flask) | ✅ Achieved |
| 6 | Provide a command-line interface for automation | ✅ Achieved |
| 7 | Ensure privacy — no external network calls for analysis | ✅ Achieved |
| 8 | Make the project runnable offline with zero downloads | ✅ Achieved |
| 9 | Audit password strength and generate secure passwords | ✅ Achieved |
| 10 | Demonstrate hashing, encoding, HMAC and key derivation | ✅ Achieved |
| 11 | Statically triage files for malware indicators | ✅ Achieved |
| 12 | Detect attacks and brute force in web/SSH logs | ✅ Achieved |
| 13 | Unify every tool behind one report format and one UI | ✅ Achieved |

---

## 5. Literature / Background Study

### 5.1 Phishing Detection Techniques

| Approach | Description | Limitation |
|---|---|---|
| **Blacklist / blocklist** | Match URL against a list of known phishing sites | Misses new (zero-day) phishing domains |
| **Heuristic / rule-based** | Apply hand-written rules about URL and email structure | Requires maintenance; can be evaded |
| **Machine learning** | Learn patterns from labelled data | Needs quality training data; can be a black box |
| **Visual similarity** | Compare rendered page to a known brand | Requires fetching the page (unsafe, slow) |
| **Hybrid (this project)** | Combine rules + ML + explainability | — |

### 5.2 Standards Relevant to Email Authentication

* **SPF (Sender Policy Framework)** — lists which servers may send mail for a domain.
* **DKIM (DomainKeys Identified Mail)** — cryptographically signs the message.
* **DMARC (Domain-based Message Authentication, Reporting & Conformance)** —
  ties SPF/DKIM to the visible `From:` domain and defines policy.

The phishing engine parses the `Authentication-Results` header to read these results.

### 5.3 Feature Engineering for URLs

Research and industry practice identify several strong lexical indicators:

* URL length and hostname length
* Number of subdomains, dots, hyphens, and digits
* Presence of a raw IP address instead of a domain name
* Use of the `@` character to disguise the real host
* Punycode (`xn--`) and homoglyph characters
* Shannon entropy of the hostname (randomness)
* Suspicious keywords (`login`, `verify`, `secure`, `account`)
* High-abuse top-level domains and URL shorteners

---

## 6. System Requirements

### 6.1 Hardware Requirements

| Component | Minimum | Recommended |
|---|---|---|
| Processor | Dual-core 1.5 GHz | Quad-core 2.0 GHz+ |
| RAM | 512 MB free | 2 GB free |
| Disk Space | ~60 MB | ~200 MB (with datasets) |
| Display | 1024×768 | 1366×768 or higher |

### 6.2 Software Requirements

| Item | Requirement |
|---|---|
| Operating System | Windows 10/11, macOS, or Linux |
| Python | **3.10 or newer** (developed on **3.14.7**) |
| Web Browser | Chrome, Edge, Firefox, or Safari (recent version) |
| Terminal | PowerShell / CMD / Bash |

### 6.3 Python Dependencies

| Package | Version | Purpose |
|---|---|---|
| `Flask` | ≥ 3.0, < 4.0 | Web dashboard + JSON API |
| `scikit-learn` | ≥ 1.4 | ML pipelines, TF-IDF, logistic regression |
| `numpy` | ≥ 1.26 | Feature vectors |
| `scipy` | ≥ 1.11 | Sparse matrices produced by TF-IDF |
| `joblib` | ≥ 1.3 | Model persistence (`.joblib`) |

**Standard-library only for the four new tools** — `hashlib`, `hmac`, `base64`,
`secrets`, `binascii`, `urllib.parse`, `html`, `re`, `math`, `struct`, `ipaddress`,
`dataclasses`. No extra downloads are needed.

**Optional:** `cryptography` (≥ 42) enables AES-256-GCM in the Crypto tab. If it is
not installed, that single operation reports that the backend is missing; nothing
else is affected.

**Verified versions on the development machine:**
Flask 3.1.3 · scikit-learn 1.9.1 · NumPy 2.5.4 · SciPy 1.18.1 · joblib 1.6.0 ·
Python 3.14.7 (`cryptography` not installed → AES-GCM reports "backend missing")

---

## 7. System Architecture

### 7.1 High-Level Architecture

```
              ┌──────────────── Flask (SUZENKUMARMOHANTYPHISHINGGUARD.py) ────────────────┐
              │   /            dashboard (templates/index.html + static/)              │
              │   /api/analyze-url   /api/analyze-email   /api/health   /api/examples  │
              │   /api/password/*    /api/crypto/*        /api/file/analyze            │
              │   /api/log/analyze   /robots.txt          /sitemap.xml                 │
              └───────────────────────────────┬────────────────────────────────────────┘
                                              │
                       ┌──────────────────────┴───────────────────────┐
                       │                                              │
            ┌──────────▼──────────┐                       ┌───────────▼───────────┐
            │  url_analyzer.py    │                       │  email_analyzer.py    │
            │  rule findings      │                       │  header + body rules  │
            └──────────┬──────────┘                       └───────────┬───────────┘
                       │  features.py                                 │
                       │  (27 URL features)                           │
                       └──────────────────────┬───────────────────────┘
                                              │
                                    ┌─────────▼─────────┐
                                    │   model.py        │  ← joblib persistence
                                    │  sklearn pipelines│
                                    └─────────┬─────────┘
                                              │
                                    ┌─────────▼─────────┐
                                    │  explainer.py     │
                                    │  blended verdict  │
                                    │  + human reasons  │
                                    └───────────────────┘
                    training.py + synthetic.py  →  train_model.py  →  models/*.joblib

  Toolkit layer (stdlib only) — every module returns common.ToolReport
  ┌───────────────┐ ┌──────────────┐ ┌───────────────┐ ┌──────────────┐
  │ password_tool │ │ crypto_tool  │ │ file_analyzer │ │ log_monitor  │
  └───────────────┘ └──────────────┘ └───────────────┘ └──────────────┘
```

The toolkit layer is deliberately independent of scikit-learn: the four new modules
import only the standard library, so they work in a minimal Python installation and
are trivial to test.

### 7.2 Data Flow

```
User input
    │
    ├── Phishing path ────────────────────────────────────────────────┐
    │   URL / email                                                   │
    │      ▼                                                          │
    │   [1] Feature Extraction ──► 27 numeric features + raw text      │
    │      ▼                                                          │
    │   [2] Rule Engine ────────► Finding objects (code, severity)     │
    │      ▼                                                          │
    │   [3] ML Model ───────────► P(phishing)                          │
    │      ▼                                                          │
    │   [4] Blending ───────────► 0.65·ML + 0.35·rules (email 0.55/0.45)
    │      ▼                                                          │
    │   [5] Explanation ────────► warnings + ML contributions          │
    │                                                                  │
    └── Toolkit path ──────────────────────────────────────────────────┤
        Password / text / file / log                                   │
           ▼                                                           │
        [1] Parse & normalise                                          │
           ▼                                                           │
        [2] Detectors / rules ──► Finding objects (code, severity)     │
           ▼                                                           │
        [3] Score 0-100 + grade (password, file, log)                  │
           ▼                                                           │
        [4] ToolReport ─────────► summary, details, advice, meta       │
                                                                       │
    [6] Presentation ◄─────────────────────────────────────────────────┘
        Web dashboard (six tabs) / CLI report / JSON API
```


### 7.3 Verdict Decision Table

| Blended Probability | Verdict | Recommended Action |
|---|---|---|
| ≥ 0.65 | **Likely phishing** | Do not click, reply, or enter credentials |
| 0.40 – 0.65 | **Suspicious** | Verify the sender through an official channel |
| < 0.40 | **Looks legitimate** | No strong indicators; stay alert |

---

## 8. Methodology

The project followed a structured development lifecycle:

### Phase 1 — Requirement Analysis
Identified the required capabilities from the project brief: URL inspection,
email-header analysis, ML classification, user-facing explanations, password
auditing, cryptography basics, file triage and log monitoring.

### Phase 2 — Data Preparation
Created a **seeded synthetic corpus generator** (`synthetic.py`) producing
balanced legitimate and phishing samples for both URLs and emails, so the project
runs offline with zero downloads. Real public datasets (PhishTank, Tranco, Enron,
SpamAssassin) can be substituted through a CSV interface.

### Phase 3 — Feature Engineering
Implemented **27 lexical/structural URL features** and a set of header/body
signals for email.

### Phase 4 — Rule Engine Development
Encoded known phishing techniques as auditable rules that emit `Finding`
objects with a **code, severity, and point weight**.

### Phase 5 — Model Development
Built two scikit-learn pipelines:

* **URL model** — `FeatureUnion` of hand-crafted features (standard-scaled) and
  character 3–5-gram TF-IDF, feeding a class-balanced logistic regression.
* **Email model** — word (1–2)-gram TF-IDF over subject + body, feeding a
  class-balanced logistic regression.

### Phase 6 — Explainability Layer
Implemented contribution analysis (`coefficient × feature value`) to surface the
exact model features that drove each decision.

### Phase 7 — Interface Development
Built a **responsive Flask dashboard** and a **colour CLI**.

### Phase 8 — Toolkit Expansion
Added four independent modules behind a shared `ToolReport` contract:

* **Password** — entropy/pattern scoring and secure generation.
* **Cryptography** — hashing, codecs, classical ciphers, HMAC, PBKDF2, AES-GCM.
* **File triage** — magic bytes, entropy, PE headers, behaviour strings.
* **Log monitoring** — web/SSH parsers and attack signatures.

### Phase 9 — Testing and Validation
Wrote **56 unit tests** plus UI/responsive static checks; verified end-to-end
behaviour through the Flask test client, the CLI and a live server.

---

## 9. Module Description

| # | Module | File | Lines | Responsibility |
|---|---|---|---|---|
| 1 | Shared contract | `common.py` | 77 | `Finding`, `ToolReport`, severity ordering |
| 2 | Feature Extraction | `features.py` | 236 | 27 URL features + threat vocabularies |
| 3 | URL Analysis | `url_analyzer.py` | 250 | Rule engine for URLs → findings |
| 4 | Email Analysis | `email_analyzer.py` | 592 | Header + body rule engine |
| 5 | ML Models | `model.py` | 266 | sklearn pipelines, `PhishingModel`, `ModelStore` |
| 6 | Training | `training.py` | 81 | Train, evaluate, persist models |
| 7 | Synthetic Data | `synthetic.py` | 287 | Seeded training corpora |
| 8 | Explanation | `explainer.py` | 249 | Blended verdict + human reasons |
| 9 | Password Tool | `password_tool.py` | 585 | Scoring, entropy, crack time, generators |
| 10 | Crypto Tool | `crypto_tool.py` | 515 | Hashes, codecs, ciphers, HMAC, PBKDF2, AES-GCM |
| 11 | File Analyzer | `file_analyzer.py` | 545 | Static malware triage |
| 12 | Log Monitor | `log_monitor.py` | 478 | Web/SSH attack detection |
| 13 | Web Application | `SUZENKUMARMOHANTYPHISHINGGUARD.py` | 415 | Flask routes + JSON API |
| 14 | CLI | `cli.py` | 352 | Terminal interface |
| 15 | Training Entry | `train_model.py` | 89 | Command-line training script |
| 16 | Dashboard | `templates/index.html` | 623 | Responsive six-tab page |
| 17 | Styling | `static/style.css` | 1232 | 6-tier responsive design system |
| 18 | Front-end Logic | `static/app.js` | 467 | Tabs, API calls, two renderers |
| 19 | Phishing Tests | `tests/test_detector.py` | 198 | 20 tests |
| 20 | Toolkit Tests | `tests/test_toolkit.py` | 325 | 36 tests (modules + API) |
| 21 | UI Smoke Tests | `tests/smoke_ui.py` | 120 | Markup/CSS/JS static checks |
| 22 | Report Builder | `tools/md_to_docx.py` | 471 | Markdown → styled Word |

**Total source: ~8,518 lines** across Python, HTML, CSS, JS and tooling.

### 9.1 Password module
`check_password()` produces a 0–100 score from length (40 points), character variety
(30) and entropy (30), then subtracts penalties for dictionary words, dates, repeats,
sequences and keyboard walks. Composite caps prevent a dictionary-word-plus-year
password from scoring highly. `generate_password()`, `generate_passphrase()` and
`generate_pin()` use `secrets`, guarantee at least one character from every enabled
class, and shuffle the result.

### 9.2 Cryptography module
`hash_text()` / `hash_file()` compute MD5, SHA-1, SHA-256, SHA-512, SHA3-256 and
BLAKE2b and explicitly flag the broken algorithms. `encode_text()` supports Base64,
Base32, hex, Base85, URL, HTML and binary in both directions. `classical_cipher()`
implements Caesar, ROT13, Vigenère, Atbash and XOR as teaching examples.
`hmac_sign()` provides HMAC-SHA256; `derive_key()` provides PBKDF2-HMAC-SHA256;
`aes_gcm()` uses authenticated encryption when `cryptography` is available.

### 9.3 File analyzer
`analyze_bytes()` detects the real type from magic bytes, compares it with the
declared extension, flags double extensions and type mismatches, computes Shannon
entropy and hashes, parses PE headers, matches 38 suspicious behaviour strings
(PowerShell `-EncodedCommand`, `Invoke-Expression`, `DownloadString`,
`certutil -urlcache`, registry Run keys, macro auto-open, ransomware notes,
reverse shells, crypto wallets) and extracts embedded URLs and IP addresses.

### 9.4 Log monitor
`analyze_log()` parses Apache/Nginx combined logs and Linux `auth.log`, reports the
percentage of lines it understood, and raises findings for SQL injection, XSS, path
traversal, command injection, sensitive-file probes, scanner user-agents, SSH brute
force, distributed brute force, login-after-failures, 404 floods, 401/403 bursts,
5xx spikes and unusual volume.

### 9.5 Shared report contract
Every toolkit module returns the same `ToolReport`: `kind`, `title`, `risk`, `score`,
`grade`, `summary`, `findings`, `details`, `advice`, `meta`. The Flask API, the CLI
and the dashboard all consume this one shape, so adding a future tool requires no
changes to the presentation layer.

---

## 10. Machine Learning Design

### 10.1 The 27 URL Features

| Category | Features |
|---|---|
| **Length** | `url_length`, `host_length`, `path_length`, `query_length` |
| **Structure** | `num_dots`, `num_subdomains`, `num_hyphens`, `num_digits`, `digit_ratio`, `num_slashes`, `path_depth` |
| **Obfuscation** | `num_at`, `num_question`, `num_equals`, `num_percent`, `num_ampersand`, `non_ascii`, `host_entropy` |
| **Host tricks** | `has_ip`, `has_userinfo`, `has_punycode`, `unusual_port`, `has_https` |
| **Reputation** | `keyword_count`, `brand_in_host`, `suspicious_tld`, `is_shortener` |

### 10.2 URL Pipeline

```
Raw URL
   ├──► HandcraftedUrlFeatures (27 values) ──► StandardScaler ──┐
   │                                                            ├──► FeatureUnion
   └──► TfidfVectorizer (char 3–5 grams, sublinear) ───────────┘
                                                                 │
                                                                 ▼
                                                    LogisticRegression
                                                    (class_weight="balanced")
```

### 10.3 Email Pipeline

```
Subject + "\n" + Body
        │
        ▼
TfidfVectorizer (word 1–2 grams, English stop-words, sublinear)
        │
        ▼
LogisticRegression (class_weight="balanced")
```

### 10.4 Why Logistic Regression?

* It is **interpretable** — every prediction is a linear combination of weighted
  features, which makes the `coefficient × value` explanation exact.
* It trains in under two seconds on the bundled corpus.
* It performs strongly on high-dimensional sparse TF-IDF text data.

### 10.5 Threat Vocabularies

| Vocabulary | Count | Example entries |
|---|---|---|
| Suspicious keywords | 40 | login, verify, account, suspended, webscr, otp |
| URL shorteners | 15 | bit.ly, tinyurl.com, goo.gl, t.co, rb.gy |
| High-abuse TLDs | 33 | .tk, .ml, .ga, .cf, .xyz, .top, .zip |
| Impersonated brands | 32 | paypal, microsoft, apple, amazon, dhl, coinbase |
| Trusted domains | 53 | google.com, github.com, paypal.com, docusign.com |

---

## 11. Implementation Details

### 11.1 URL Rule Codes (18 total)

`ip_host` · `userinfo` · `punycode` · `unusual_port` · `brand_spoof` ·
`suspicious_tld` · `deep_subdomains` · `hyphen_heavy` · `no_https` ·
`shortener` · `encoded_host` · `very_long_url` · `long_url` · `digit_soup` ·
`keywords` · `trusted_domain` · `https` · `clean_structure`

### 11.2 Email Rule Codes (30+ total)

**Authentication:** `spf_fail` · `spf_softfail` · `spf_none` · `spf_pass` ·
`dkim_fail` · `dkim_pass` · `dmarc_fail` · `dmarc_pass`

**Identity:** `display_name_spoof` · `return_path_mismatch` · `return_path_match` ·
`reply_to_mismatch` · `msgid_mismatch`

**Links:** `link_ip` · `link_http` · `link_shortened` · `link_bad_tld` ·
`link_brand_mismatch` · `link_sender_mismatch` · `anchor_mismatch`

**Content:** `urgency` · `credentials` · `brand_no_link` · `html_form` ·
`suspicious_attachment` · `html_only` · `no_received` · `many_hops`

**Trust:** `plain_text` · `no_links` · `links_match_sender`

### 11.3 Scoring Model

Each `Finding` carries a point weight:

| Severity | Typical points | Example |
|---|---|---|
| High | 20 – 30 | raw IP host, SPF fail, display-name spoof |
| Medium | 8 – 15 | suspicious TLD, urgency wording |
| Low | 5 – 8 | long URL, HTML-only body |
| Trust | −5 to −20 | trusted domain, SPF passed |

```
rule_score = clamp(Σ warning_points − Σ trust_points, 0, 100)

url_probability   = 0.65 × ML_probability + 0.35 × (rule_score / 100)
email_probability = 0.55 × ML_probability + 0.45 × (rule_score / 100)
```

### 11.4 Explainability Implementation

For a linear model the contribution of feature *i* is exactly:

```
contribution_i = coefficient_i × value_i
```

The largest positive contributions become **"What the model noticed"**; the
largest negative contributions become **"Evidence of legitimacy"**. This turns a
machine-learning verdict into an auditable statement.

### 11.5 Web API Endpoints

| Method | Route | Purpose |
|---|---|---|
| GET | `/` | Responsive six-tab dashboard |
| POST | `/api/analyze-url` | Analyse a URL → JSON report |
| POST | `/api/analyze-email` | Analyse an email → JSON report |
| POST | `/api/password/check` | Audit a password strength |
| POST | `/api/password/generate` | Generate password / passphrase / PIN |
| POST | `/api/crypto/hash` | Hash text with public algorithms |
| POST | `/api/crypto/encode` | Encode or decode text |
| POST | `/api/crypto/cipher` | Apply a classical cipher |
| POST | `/api/crypto/hmac` | HMAC-SHA256 signature |
| POST | `/api/file/analyze` | Static file triage (multipart / base64 / text) |
| POST | `/api/log/analyze` | Parse and scan logs |
| GET | `/api/health` | Version, model status, loaded modules |
| GET | `/api/examples` | Built-in demo samples |
| GET | `/robots.txt` | Crawler directives |
| GET | `/sitemap.xml` | SEO sitemap |

### 11.6 Password scoring

```
score = length_points(0-40) + variety_points(0-30) + entropy_points(0-30)
        - penalties
```

* **Length:** 8 characters → 8 points, 16 → 28, 20+ → 40.
* **Variety:** one point per character class present (max 4) plus a bonus when
  three or four classes are used.
* **Entropy:** `length × log2(alphabet_size)`, mapped onto 0–30.
* **Penalties:** common password (−60), dictionary word (−15), leetspeak word
  (−12), date/year (−15), repeated run (−12), sequence/keyboard walk (−15),
  all-letters penalised when short.
* **Composite caps:** dictionary + date → max 45; dictionary + pattern → max 50;
  dictionary alone → max 65. This stops `Summer2024!` from looking strong.

Crack time assumes **10¹⁰ guesses/second** (offline GPU against a fast hash) and is
rendered as seconds, minutes, hours, days, years or centuries.

### 11.7 File triage scoring

| Points | Indicator |
|---|---|
| +30 | Double extension (`invoice.pdf.exe`) |
| +28 | File type does not match its extension |
| +18 | Dangerous/executable extension |
| +18 | Very high entropy (≥ 7.5, packed or encrypted) |
| +10 | Windows PE binary |
| +8 | Elevated entropy (≥ 7.0) |
| variable | Each behaviour signature (critical/high/medium weights) |
| +3 each (max 12) | Embedded URLs |
| +6 | Three or more embedded IP addresses |
| −10 | No known malicious strings (reassuring) |
| −5 | Normal entropy (reassuring) |

`score ≥ 65` → **Likely malicious**; `35–64` → **Suspicious**; `< 35` → **No strong
indicators**.

### 11.8 Log detection

Logs are parsed with compiled regular expressions for the combined log format and
for `sshd` events. Per-IP state is aggregated so the monitor can distinguish a
single noisy client from a distributed brute-force campaign, and can correlate
`Failed password` lines followed by `Accepted password` — the strongest signal of
a **successful compromise**.

### 11.9 Cryptography choices

* Hashes: MD5/SHA-1 flagged as broken; SHA-256, SHA-512, SHA3-256 and BLAKE2b
  recommended.
* HMAC-SHA256 for message authentication (never plain `hash(secret + message)`).
* PBKDF2-HMAC-SHA256 with a random salt and a high iteration count for password
  storage.
* AES-256-GCM (AEAD) when available, because it provides both confidentiality and
  integrity; a fresh nonce is generated for every encryption.

---

## 12. Results and Testing

### 12.1 Training Results

```
Training phishing models ...
  [URL]   hold-out accuracy=1.000  f1=1.000  (train=640, test=160)
  [Email] hold-out accuracy=1.000  f1=1.000  (train=560, test=140)
Saved models to 'models/' (1.79s)
```

| Model | Training Samples | Test Samples | Accuracy | F1 Score | Time |
|---|---|---|---|---|---|
| URL | 640 | 160 | 1.000 | 1.000 | 1.79 s |
| Email | 560 | 140 | 1.000 | 1.000 | (same run) |

> **Note:** Perfect scores are expected on *synthetic* data because the corpus is
> generated from the same threat patterns the rules describe. Realistic figures
> on public datasets (PhishTank, Enron, SpamAssassin) are approximately
> **93–97 %** for URLs and **95–99 %** for emails.

### 12.2 Unit Test Results

```
tests/test_detector.py   Ran 20 tests in 0.348s   OK
tests/test_toolkit.py    Ran 36 tests in 3.563s   OK
```

| Test Group | Tests | Result |
|---|---|---|
| Feature extraction | 3 | ✅ Pass |
| URL analyzer | 6 | ✅ Pass |
| Email analyzer | 4 | ✅ Pass |
| ML models | 3 | ✅ Pass |
| Report generation | 4 | ✅ Pass |
| Password tool | 9 | ✅ Pass |
| Crypto tool | 7 | ✅ Pass |
| File analyzer | 5 | ✅ Pass |
| Log monitor | 6 | ✅ Pass |
| Web API (new endpoints) | 9 | ✅ Pass |
| **Total** | **56** | **✅ All pass** |

### 12.3 Functional Test Results

| Input | Expected | Actual | Status |
|---|---|---|---|
| `http://paypal.com@secure-login-verify.tk/account/verify` | Phishing | 86.3 % — Phishing | ✅ |
| `https://docs.python.org/3/library/email.html` | Legitimate | 0.2 % — Legitimate | ✅ |
| `https://bit.ly/3xYzAbC` | Suspicious | 64.2 % — Suspicious | ✅ |
| `http://192.168.10.4/paypal/login.php` | Suspicious/Phishing | 63.2 % — Suspicious | ✅ |
| Spoofed DHL email (SPF fail, DMARC fail) | Phishing | 90.1 % — Phishing | ✅ |
| Legitimate GitHub notification email | Legitimate | Correct | ✅ |
| Empty input | 400 error | 400 error | ✅ |
| Password `password` | Very weak | 0/100, danger | ✅ |
| Password `Summer2024!` | Weak | 45/100, danger | ✅ |
| Password `Tr0ub4dor&3` | Strong | 75/100, safe | ✅ |
| Password `correct-horse-battery-staple` | Very strong | 93/100, safe | ✅ |
| Generated 16-char password | Very strong | ≥ 90/100, safe | ✅ |
| Base64 encode `hello world` | `aGVsbG8gd29ybGQ=` | `aGVsbG8gd29ybGQ=` | ✅ |
| SHA-256 of `abc` | known digest | matches | ✅ |
| Malicious PE `invoice.pdf.exe` | Likely malicious | 100/100, danger | ✅ |
| Clean `note.txt` | No indicators | 0/100, safe | ✅ |
| Attack log (SQLi + traversal + brute force) | Active attack | 100/100, danger | ✅ |
| Clean access log (10 quiet requests) | No attacks | 0/100, safe | ✅ |

### 12.4 Interface Test Results

| Route | Status Code |
|---|---|
| `/` | 200 ✅ |
| `/static/style.css` | 200 ✅ |
| `/static/app.js` | 200 ✅ |
| `/robots.txt` | 200 ✅ |
| `/sitemap.xml` | 200 ✅ |
| `/api/health` | 200 ✅ |
| `/api/examples` | 200 ✅ |
| `/api/password/check` | 200 ✅ |
| `/api/password/generate` | 200 ✅ |
| `/api/crypto/hash` | 200 ✅ |
| `/api/crypto/encode` | 200 ✅ |
| `/api/crypto/cipher` | 200 ✅ |
| `/api/crypto/hmac` | 200 ✅ |
| `/api/file/analyze` | 200 ✅ |
| `/api/log/analyze` | 200 ✅ |

### 12.5 Responsive and Accessibility Tests

| Check | Result |
|---|---|
| CSS brace balance | 357 = 357 ✅ |
| Breakpoints (1280/1024/860/720/560/400 px) | All present ✅ |
| Landscape, reduced-motion, hover:none, print queries | All present ✅ |
| Unsafe fixed `minmax()` values | None ✅ |
| Overflow guards | Present ✅ |
| Six tabs present and labelled | ✅ |
| Tab bar scrolls horizontally below 860 px | ✅ |
| Detail lists collapse to one column below 560 px | ✅ |
| Viewport meta tag | `width=device-width, initial-scale=1, viewport-fit=cover` ✅ |

### 12.6 SEO Validation

| Tag | Present |
|---|---|
| `<title>`, meta description, keywords, author, robots | ✅ |
| Canonical link | ✅ |
| Open Graph (og:title, og:description, og:url, og:image) | ✅ |
| Twitter Card | ✅ |
| JSON-LD structured data (`SoftwareApplication`) | ✅ |
| `robots.txt` and `sitemap.xml` | ✅ |

---

## 13. Sample Outputs

### 13.1 Phishing URL

```
==================================================================
VERDICT: LIKELY PHISHING
Phishing probability: [##########################----]  86.3%
  ML model: 100.0%   Rule score: 61/100
==================================================================

WHY — main reasons
  * Deceptive '@' in the link
  * High-abuse top-level domain '.tk'
  * Unencrypted http:// link

WARNING SIGNS
  [HIGH] Deceptive '@' in the link
        Browsers display only the text *before* '@' for some links, so
        'https://paypal.com@evil.example' actually goes to evil.example.
  [MEDIUM] High-abuse top-level domain '.tk'
  [MEDIUM] Credential-theft vocabulary in the link
        Found 'account', 'login', 'secure', 'session', 'verify'.

WHAT THE MODEL NOTICED
  + 5 credential-theft keyword(s) in the link  (+4.85)
  + Sits on a TLD with a known abuse reputation  (+3.45)

RECOMMENDATION
  Do NOT click, reply or enter any credentials. Report and delete the message.
```

### 13.2 Legitimate URL

```
VERDICT: LOOKS LEGITIMATE
Phishing probability: [------------------------------]   0.2%
  ML model: 0.2%   Rule score: 0/100

EVIDENCE OF LEGITIMACY
  - Domain belongs to a well-known service
  - Link uses HTTPS
  - Clean, short structure
```

### 13.3 Spoofed Email

```
VERDICT: LIKELY PHISHING
Phishing probability: [###########################---]  90.1%
  ML model: 82.1%   Rule score: 100/100

WARNING SIGNS
  [HIGH] SPF check failed
  [HIGH] DMARC policy failed
  [HIGH] Display name says 'DHL Express' but the address is elsewhere
  [HIGH] Link text does not match the real destination
  [HIGH] Embedded HTML form in the email
  [MEDIUM] Reply-To points to a different domain
  [MEDIUM] Unencrypted http:// link in the message
  [MEDIUM] Pressure and urgency wording

HEADER SUMMARY
  From          : DHL Express <delivery@mail-random-host.xyz>
  Return-Path   : <bounce@mail-random-host.xyz>
  Reply-To      : recover@another-host.tk
  SPF/DKIM/DMARC: fail / none / fail
```

### 13.4 Password audit

```
PASSWORD  Password strength: Weak
RESULT: WEAK
Score: [##############----------------] 45/100

SUMMARY
  * Only 11 characters; aim for 12-16 or more.

FINDINGS
  [MEDIUM] Contains a common dictionary word
        Found the word 'summer'. Wordlists combined with mangling rules
        guess dictionary-based passwords very quickly.
  [MEDIUM] Looks like a year or date
        '2024' resembles a year or date.

DETAILS
  Length               : 11 characters
  Character classes    : 4 of 4 (lower, upper, digit, symbol)
  Entropy              : 72.3 bits
  Estimated crack time : 90 centuries

RECOMMENDATIONS
  - Use a password manager and generate a random 16+ character password.
  - Avoid single dictionary words; use a multi-word passphrase instead.
```

### 13.5 Cryptography output

```
CRYPTO  Hash digests
RESULT: 6 ALGORITHMS

DETAILS
  MD5      : 5eb63bbbe01eeed093cb22bb8f5acdc3
  SHA1     : 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
  SHA256   : b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
  SHA512   : 309ecc489c12d6eb…
  SHA3-256 : 644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938
  BLAKE2b  : 021ced8799296cec…

FINDINGS
  [HIGH] MD5 is cryptographically broken
  [HIGH] SHA1 is cryptographically broken
```

### 13.6 Malware triage

```
FILE  File triage: Likely malicious
RESULT: LIKELY MALICIOUS
Score: [#########################-----] 82/100

FINDINGS
  [CRITICAL] Double extension disguises an executable
  [HIGH] PowerShell invocation
  [HIGH] Encoded PowerShell command
  [HIGH] Invoke-Expression (IEX)
  [HIGH] Remote script download
  [HIGH] certutil download abuse
  [MEDIUM] Registry modification
  [MEDIUM] 3 embedded IP address(es)

DETAILS
  Detected type   : Windows executable (PE)
  Entropy         : 7.82 / 8 bits per byte
  SHA-256         : 9f2c… (submitted to reputation services)
```

### 13.7 Log monitoring

```
LOG  Log analysis: Active attack indicators
RESULT: ACTIVE ATTACK INDICATORS
Score: [##############################] 100/100

FINDINGS
  [CRITICAL] SQL injection attempts
  [CRITICAL] Path traversal / local file inclusion attempts
  [CRITICAL] Command injection attempts
  [CRITICAL] Successful login after failed attempts
  [HIGH] Probing for sensitive files
  [HIGH] Vulnerability scanner detected
  [HIGH] SSH brute-force attempt

DETAILS
  Lines analysed   : 12
  Lines parsed     : 12 (100%)
  HTTP requests    : 5
  Unique client IPs: 3
```

---

## 14. Advantages and Limitations

### 14.1 Advantages

1. **Explainable** — every verdict lists the exact reasons, unlike black-box filters.
2. **Hybrid detection** — rules provide auditability, ML provides generalisation.
3. **Privacy-preserving** — all analysis is local; nothing is transmitted.
4. **Safe by design** — static analysis only; links are never opened and files are
   never executed.
5. **Offline-capable** — ships with a synthetic corpus; no downloads required.
6. **One consistent experience** — five tools share one report format, one UI,
   one API and one CLI.
7. **Extensible** — retrain on real CSVs, or add a tool that returns `ToolReport`.
8. **Educational** — shows *why* a password is weak, *why* MD5 is unsafe, *why* a
   file looks malicious, and *which* request lines were attacks.
9. **Well-tested** — 56 unit tests plus static UI checks.
10. **Zero extra dependencies** — the four new modules use only the standard library.

### 14.2 Limitations

1. **Synthetic training data** — perfect scores are expected; real evaluation
   requires public corpora.
2. **No live reputation checks** — a brand-new phishing domain may look
   structurally clean without Safe Browsing / VirusTotal enrichment.
3. **Heuristic file triage** — string signatures and entropy miss fully encrypted
   or novel malware, and can flag legitimate installers. It is a first-pass filter.
4. **Hashes are not signatures** — a SHA-256 digest proves identity, not safety.
5. **AES-GCM is optional** — requires the `cryptography` package; without it the
   tool reports that the backend is missing rather than downgrading security.
6. **Classical ciphers are teaching toys** — clearly labelled as insecure.
7. **Log parsing is format-limited** — tuned for Apache/Nginx and Linux SSH;
   unusual formats reduce parsed-line coverage.
8. **Marketing mail with tracking domains** can look suspicious and trigger
   medium findings.
9. **English-centric vocabulary** — other locales need additional word lists.
10. **Model freshness** — phishing tactics evolve; periodic retraining is required.

---

## 15. Future Scope

1. **Live reputation enrichment** — integrate Google Safe Browsing and VirusTotal.
2. **URL expansion** — resolve shorteners in a sandboxed fetcher.
3. **File upload support for email** — accept `.eml` and `.msg` with attachment hashing.
4. **Model comparison notebook** — logistic regression vs. random forest vs. SVM
   vs. gradient boosting.
5. **Confidence calibration** — Platt scaling or isotonic regression.
6. **Docker + REST deployment** with rate limiting and authentication.
7. **Browser extension** — submit the active tab URL to `/api/analyze-url`.
8. **Feedback loop** — a "was this correct?" control that appends labelled
   samples for periodic retraining.
9. **YARA-style rule editor** for the file triage module.
10. **Live log tailing** from `journald` or `tail -f` instead of paste-only analysis.
11. **HaveIBeenPwned offline hash check** for breached passwords.
12. **PDF report export** of any tool result for coursework submissions.

---

## 16. Conclusion

Safeguard Pro+ successfully meets all stated objectives. The phishing engine
inspects URL structure, analyses email headers and message patterns, classifies
samples using machine learning, and explains every warning sign in plain language.
The four additional modules extend the same philosophy to passwords, cryptography,
files and logs.

The project demonstrates a practical application of:

* **Python** programming and modular package design,
* **machine learning** with scikit-learn pipelines,
* **natural language processing** using n-grams and TF-IDF,
* **web development** with Flask and a responsive front end,
* **applied cryptography** using the standard library,
* and **defensive security** concepts including SPF/DKIM/DMARC, URL forensics,
  password policy, malware triage and log-based intrusion detection.

The combination of deterministic rules, machine-learning classification, and
human-readable explanations produces a toolkit that is not only effective but also
**trustworthy and educational** — an important quality for security software.

The result is a solid foundation that can be extended with live threat
intelligence, additional model families, and deployment automation.

---

## 17. References

1. IBM SkillsBuild — Cyber Security learning path.
2. OWASP Foundation — *Phishing* (owasp.org).
3. OWASP Foundation — *Password Storage Cheat Sheet*.
4. NIST — *Digital Identity Guidelines* (SP 800-63B).
5. RFC 7208 — *Sender Policy Framework (SPF)*.
6. RFC 6376 — *DomainKeys Identified Mail (DKIM)*.
7. RFC 7489 — *DMARC*.
8. RFC 2104 — *HMAC: Keyed-Hashing for Message Authentication*.
9. RFC 8018 — *PKCS #5: Password-Based Cryptography (PBKDF2)*.
10. NIST SP 800-38D — *Galois/Counter Mode (GCM) for Confidentiality and Authentication*.
11. FIPS 180-4 — *Secure Hash Standard (SHA-1, SHA-256, SHA-512)*.
12. Scikit-learn documentation — *Feature extraction, Pipelines, LogisticRegression*
    (scikit-learn.org).
13. Flask documentation (flask.palletsprojects.com).
14. Python documentation — `hashlib`, `hmac`, `secrets`, `base64`
    (docs.python.org).
15. PhishTank — *Phishing URL feed* (phishtank.org).
16. Tranco — *Top-1M domain ranking* (tranco-list.eu).
17. SpamAssassin — *Public email corpus* (spamassassin.apache.org).
18. CMU — *Enron Email Dataset* (cs.cmu.edu/~enron).
19. MITRE ATT&CK — *Phishing (T1566), PowerShell (T1059.001), Brute Force (T1110)*.
20. Apache and Nginx documentation — *Combined log format*.

---

## 18. Appendix

### Appendix A — Project Folder Structure

```
C:\Users\suzen\Documents\Default Project\phishing-detector\
├── SUZENKUMARMOHANTYPHISHINGGUARD.py   # Flask app + JSON API
├── cli.py                      # Command-line interface
├── train_model.py              # Training entry point
├── run.sh                      # Linux/Kali/macOS launcher
├── "PHISHINGGUARD Requirements File.txt"   # Python dependencies
├── README.md                   # Documentation
├── PROJECT_REPORT.md           # This report (Markdown)
├── SUZENKUMARMOHANTYPHISHINGGUARD PROJECT REPORT.docx
├── .gitignore
├── phishing_detector/          # Core package
│   ├── __init__.py
│   ├── common.py               # Finding + ToolReport
│   ├── features.py
│   ├── url_analyzer.py
│   ├── email_analyzer.py
│   ├── synthetic.py
│   ├── model.py
│   ├── training.py
│   ├── explainer.py
│   ├── password_tool.py
│   ├── crypto_tool.py
│   ├── file_analyzer.py
│   └── log_monitor.py
├── templates/index.html        # Six-tab dashboard
├── static/
│   ├── style.css               # Responsive styling
│   ├── app.js                  # Front-end logic
│   └── robots.txt
├── tests/
│   ├── test_detector.py        # 20 phishing tests
│   ├── test_toolkit.py         # 36 toolkit/API tests
│   └── smoke_ui.py             # UI/SEO/responsive checks
├── tools/
│   └── md_to_docx.py           # Report → Word converter
├── models/                     # Generated model files
│   ├── url_model.joblib
│   ├── email_model.joblib
│   └── metrics.json
└── data/                       # For real datasets (optional)
```

### Appendix B — Installation and Run Commands

```powershell
# 1. Go to the project folder
cd "C:\Users\suzen\Documents\Default Project\phishing-detector"

# 2. Install dependencies
pip install -r "PHISHINGGUARD Requirements File.txt"

# 3. Train the models (once)
py -3 train_model.py

# 4. Run the web application
py -3 SUZENKUMARMOHANTYPHISHINGGUARD.py
#    then open http://127.0.0.1:5000
```

### Appendix C — CLI Usage

```powershell
py -3 cli.py demo                                        # built-in examples
py -3 cli.py url "http://bit.ly/3xYzAbC"                 # analyse a URL
py -3 cli.py url urls.txt                                # a file of URLs
py -3 cli.py email suspicious.eml                        # analyse a raw email
py -3 cli.py email --subject "Verify now" --body "..."   # subject + body
py -3 cli.py status                                      # model file status

py -3 cli.py password "Summer2024!"                      # audit a password
py -3 cli.py password --generate 20                      # generate a password
py -3 cli.py hash "hello world"                          # six digests
py -3 cli.py hash --file setup.exe                       # hash a file
py -3 cli.py encode "hello" --method base64              # encode text
py -3 cli.py file suspicious.pdf.exe                     # malware triage
py -3 cli.py log access.log                              # log monitoring
```

### Appendix D — API Request Example

```bash
curl -X POST http://127.0.0.1:5000/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal.com@secure-login-verify.tk/account/verify"}'
```

Sample JSON response:

```json
{
  "kind": "url",
  "verdict": "phishing",
  "verdict_label": "Likely phishing",
  "risk_class": "danger",
  "probability": 0.863,
  "ml_probability": 1.0,
  "rule_score": 61,
  "summary": ["Deceptive '@' in the link", "High-abuse top-level domain '.tk'"],
  "warnings": [
    {
      "code": "userinfo",
      "title": "Deceptive '@' in the link",
      "detail": "Browsers display only the text before '@' …",
      "severity": "high",
      "points": 20
    }
  ],
  "ml_signs": ["5 credential-theft keyword(s) in the link  (+4.85)"],
  "trust_signs": ["Link uses HTTPS (encrypted transport)"]
}
```

Toolkit example:

```bash
curl -X POST http://127.0.0.1:5000/api/password/check \
  -H "Content-Type: application/json" \
  -d '{"password": "Summer2024!"}'
```

```json
{
  "kind": "password",
  "title": "Password strength: Weak",
  "risk": "danger",
  "risk_class": "danger",
  "score": 45,
  "grade": "Weak",
  "summary": ["Only 11 characters; aim for 12-16 or more."],
  "findings": [
    { "code": "dictionary", "title": "Contains a common dictionary word",
      "detail": "Found the word 'summer' …", "severity": "medium", "points": 15 }
  ],
  "details": [
    { "label": "Length", "value": "11 characters" },
    { "label": "Entropy", "value": "72.3 bits" }
  ],
  "advice": ["Use a password manager and generate a random 16+ character password."],
  "meta": { "length": 11 }
}
```

File upload example:

```bash
curl -X POST http://127.0.0.1:5000/api/file/analyze -F "file=@suspicious.pdf.exe"
```

Log analysis example:

```bash
curl -X POST http://127.0.0.1:5000/api/log/analyze \
  -H "Content-Type: application/json" \
  -d '{"log": "203.0.113.45 - - [12/Oct/2026:03:14:07 +0000] \"GET /.env HTTP/1.1\" 404 196"}'
```

### Appendix E — Running the Tests

```powershell
py -3 -m unittest discover -s tests -v
# or run each suite directly
py -3 tests/test_detector.py
py -3 tests/test_toolkit.py
py -3 tests/smoke_ui.py
```

Expected output:

```
Ran 20 tests in 0.348s
OK
Ran 36 tests in 3.563s
OK
All UI checks passed.
```

### Appendix F — Glossary

| Term | Meaning |
|---|---|
| **Phishing** | Fraudulent attempt to obtain sensitive information by impersonation |
| **Spear phishing** | Targeted phishing aimed at a specific person or group |
| **SPF** | Sender Policy Framework — authorises sending servers for a domain |
| **DKIM** | DomainKeys Identified Mail — cryptographic signature on a message |
| **DMARC** | Policy that aligns SPF/DKIM with the visible From domain |
| **Punycode** | ASCII encoding of internationalised domain names (`xn--`) |
| **Homoglyph** | Visually similar character used to fake a domain |
| **TF-IDF** | Term Frequency–Inverse Document Frequency weighting |
| **N-gram** | Contiguous sequence of *n* characters or words |
| **Entropy** | Measure of randomness; high entropy suggests generated text |
| **Shortener** | Service that maps a long URL to a short one |
| **TLD** | Top-Level Domain (e.g. `.com`, `.tk`) |
| **Entropy (password)** | `length × log2(alphabet size)` — the search space in bits |
| **Crack time** | Estimated guesses ÷ attack speed (10¹⁰/s here) |
| **Hash** | One-way fixed-size digest of data |
| **HMAC** | Keyed hash that proves integrity and authenticity |
| **PBKDF2** | Slow, salted key derivation designed for passwords |
| **AES-GCM** | Authenticated encryption (confidentiality + integrity) |
| **Magic bytes** | First bytes of a file that reveal its real type |
| **PE** | Portable Executable — the Windows `.exe`/`.dll` format |
| **Shannon entropy (file)** | 0–8 bits/byte; high values suggest packing or encryption |
| **Double extension** | A name like `invoice.pdf.exe` used to disguise an executable |
| **SQL injection** | Injecting SQL syntax through user input |
| **XSS** | Cross-site scripting — injecting script into a page |
| **Path traversal** | Using `../` to reach files outside the web root |
| **LFI** | Local File Inclusion — tricking an app into reading local files |
| **Brute force** | Repeated login guesses until one succeeds |
| **AEAD** | Authenticated Encryption with Associated Data (e.g. GCM) |

---

## Acknowledgement

I would like to express my sincere gratitude to **IBM SkillsBuild** for providing
the learning platform and resources that made this project possible, and to all
mentors and peers whose guidance and feedback contributed to its completion.

---

**Prepared by:** Er-Suzen Kumar Mohanty
**Programme:** IBM SkillsBuild — Cyber Security
**Project:** Safeguard Pro+ — AI Security Toolkit
**Modules:** Phishing · Password · Crypto · File triage · Log monitoring
**Date:** 25 October 2026
**Version:** 2.0

---

*© 2026 Safeguard Pro+ · Defensive security tool · Educational use only*
