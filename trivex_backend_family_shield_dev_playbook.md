# TriVex --- Backend Plan, Family Shield & Development Playbook

**Purpose:** Technical implementation reference for the project lead\
**Platform:** Chrome Extension Manifest V3 + Python offline evaluation\
**Principle:** Implement, test, review, and stabilize one subsystem
before starting the next.

## 1. Backend plan

### 1.1 Architecture

-   **JavaScript extension:** runs URL analysis locally in the browser.
-   **Python backend folder:** provides a reference implementation and
    offline evaluation; a hosted API server is not required for the
    first version.
-   **System A:** rule-based detector.
-   **System B:** weighted risk score.
-   **System C:** hybrid/AI-assisted judge that compares A and B,
    explains disagreements, and handles uncertainty.
-   **Page monitor:** separate module for selected signals after
    navigation.
-   **Family Shield:** separate content policy that reuses URL parsing
    but does not treat phishing signals as adult-content evidence.

### 1.2 URL parsing and features

Parse and validate URLs before detection. Extract scheme, hostname,
path, URL length, and six shared features. Count hostname dots only in
the parsed hostname, not in the entire URL. Handle IPv4/IPv6 and
malformed URLs. Define keyword matching, case handling, and
repeated-symbol behavior consistently in JavaScript and Python.

### 1.3 System A --- rules

Flag when any condition applies: - IP address in hostname. - URL length
\> 75 characters. - More than 3 dots in the parsed hostname. - `@` or
multiple hyphens. - A targeted keyword appears and HTTPS is absent.

Keywords: `secure`, `login`, `verify`, `update`, `account`, `banking`.

### 1.4 System B --- weighted scoring

  Feature                       Points
  --------------------------- --------
  IP address in hostname            35
  Suspicious symbols                30
  More than 3 hostname dots         20
  Targeted keyword                  15
  URL length \> 75                  10
  HTTPS absent                      10
  **Flagging threshold**        **45**

Recommended baseline: each feature category contributes at most once.
Document any changes.

### 1.5 System C --- hybrid/AI-assisted decision

1.  Run A and B independently.
2.  Preserve their raw verdicts, scores, and reasons.
3.  Apply a documented deterministic baseline policy.
4.  Report disagreement explicitly.
5.  If an LLM is added, treat page text as untrusted input and never
    allow it to override hard safety rules.
6.  Do not describe an LLM as a trained ML model. A trained model must
    be trained and evaluated separately.

A sensible baseline policy can flag when A flags; otherwise use B's
verdict, while surfacing disagreement. Treat this as a proposal to
validate, not as a proven optimal policy.

### 1.6 Result contract

Return a structured result containing: - input URL or a privacy-safe
representation, - validation status, - extracted features, - System A
verdict and reasons, - System B score, threshold, verdict, and
reasons, - System C verdict and disagreement indicator, - page-monitor
findings if available, - final action and explanation.

"No high-risk indicators detected" must not be presented as proof that a
URL is safe.

### 1.7 Evaluation

Use a versioned, labelled dataset. Run A, B, and C independently and
report confusion matrix, accuracy, precision, recall, F1-score, and
false-positive rate. Record dataset provenance. If ML is later added,
prevent duplicates and leakage between train/test splits. Do not present
research-paper metrics as TriVex results.

## 2. Family Shield

**Default configuration:** Balanced filtering; local blocking;
adult-content blocking enabled; high-confidence phishing blocking
enabled; continuous page monitoring enabled.

### 2.1 Separate policies

Maintain separate outcomes for: - `phishing_risk` - `content_category`

The phishing rules alone are not sufficient to identify adult content.
Use a maintained category source and/or a separately tested content
classifier.

### 2.2 Balanced policy

-   High-confidence phishing evidence: block and show the local warning
    page.
-   High-confidence adult-content classification: block and show the
    local family-protection page.
-   Moderate, conflicting, or incomplete evidence: use a
    caution/restricted page or the documented fallback policy.
-   Low evidence: allow while supported monitoring continues.
-   Unsupported pages or unavailable data sources: show a clear
    limitation; do not claim the page is safe.

Define and test confidence thresholds; do not rely on an arbitrary
LLM-generated confidence score.

### 2.3 Local blocking and educational alternatives

-   Use a packaged TriVex block page as the default.
-   Validate any URL passed to the block page; do not inject it into
    HTML unsafely.
-   Exclude extension pages from detection and prevent redirect loops.
-   Never automatically reopen a blocked URL.
-   Offer only parent-approved educational destinations, and open them
    only after a user action.
-   Do not redirect to arbitrary URLs supplied by page content.

### 2.4 Continuous monitoring

Inspect selected page signals only. Use bounded/debounced DOM
observation; avoid excessive CPU usage. Never read or store passwords or
form values. Reevaluate when meaningful evidence changes, not on every
mutation. Make permissions and unsupported-page behavior clear.

### 2.5 Incognito

Chrome requires the user to enable **Allow in incognito**. The extension
cannot enable this silently. Test both enabled and disabled states. Do
not persist incognito browsing history as ordinary history. Explain that
the extension cannot prevent its own removal, permission revocation, or
use of another browser.

## 3. Security requirements

### 3.1 Accounts and passwords

First decide whether accounts are truly needed. A local-only extension
may not require an account. - Use established authentication if accounts
are implemented. - Never store plaintext passwords or a reversible
password copy. - Minimize personal profile data. - Provide clear
sign-out and deletion procedures where applicable. - A password gate
cannot prevent someone with browser-profile control from disabling or
modifying the extension.

### 3.2 Encryption and local storage

-   Define the threat model before promising encryption.
-   Specify which data is encrypted, where keys are stored, and who can
    decrypt it.
-   Do not assume extension storage is automatically encrypted with a
    user-only key.
-   A key stored next to encrypted data offers limited protection
    against someone controlling the browser profile.
-   Do not promise that a password can prevent extension disablement or
    permission revocation.

### 3.3 Gemini API key and external AI

-   Gemini integration is optional and must be off by default.
-   Explain what data is sent externally before enabling it.
-   Never hard-code, commit, or log API keys.
-   A user-provided key stored locally may still be extractable by
    someone who controls the browser profile.
-   Prefer local detection. If external AI is used, send only the
    minimum structured evidence necessary.
-   Treat page content as untrusted data; ignore instructions contained
    in it.
-   Handle missing, invalid, or rate-limited keys gracefully.
-   Do not send visited URLs or page contents externally by default.

### 3.4 Permissions and data minimization

Request only permissions required by implemented features. Avoid storing
browsing history or raw page content. Do not claim tamper-proof parental
controls; device/browser management is required for stronger
enforcement.

## 4. Development TODO list --- 12 phases

**Rule:** Do not implement every subsystem together. Each phase should
pass its acceptance criteria before dependent work begins. Keep `main`
runnable.

### Phase 0 --- Repository audit and requirements

-   Inspect current files and teammate changes.
-   Record current behavior, requirements, interfaces, permissions, and
    tests.
-   Do not overwrite existing work without review.
-   **Done when:** baseline and next phase are agreed.

### Phase 1 --- URL parsing and feature extraction

-   Implement validation and the six shared features in JavaScript and
    Python.
-   Test malformed URLs, IPv4/IPv6, hostname dots, length, keywords,
    symbols, and HTTPS.
-   **Done when:** feature tests pass and JS/Python outputs match.

### Phase 2 --- System A

-   Implement only the fixed rules and explanations.
-   Test each rule independently and at boundary conditions.
-   **Done when:** System A tests pass.

### Phase 3 --- System B

-   Implement weights, score breakdown, and threshold.
-   Test each feature contribution and threshold boundaries.
-   **Done when:** expected scores are reproducible.

### Phase 4 --- System C

-   Combine A/B outputs using a documented policy.
-   Report disagreements and uncertainty.
-   Evaluate any LLM/ML addition separately.
-   **Done when:** deterministic decisions and explanations pass tests.

### Phase 5 --- Popup integration

-   Connect the existing popup to the stable detector.
-   Implement loading, success, invalid input, error, warning, and
    result states.
-   **Done when:** manual URL analysis works end to end.

### Phase 6 --- Offline evaluation

-   Create a labelled, versioned dataset with provenance.
-   Report confusion matrix, accuracy, precision, recall, F1, and
    false-positive rate.
-   Prevent duplicate leakage if ML is added.
-   **Done when:** evaluation is repeatable and metrics are actual
    measured results.

### Phase 7 --- Phishing blocking and local block page

-   Add minimal necessary permissions and safe blocking behavior.
-   Test no loops, no self-blocking, and no arbitrary redirects.
-   **Done when:** high-confidence test cases block safely.

### Phase 8 --- Continuous page monitoring

-   Add selected DOM indicators and debounced updates.
-   Avoid credentials/form values and unnecessary persistence.
-   Measure performance impact.
-   **Done when:** monitoring works on supported test pages without
    excessive resource use.

### Phase 9 --- Family Shield

-   Add balanced policy settings, category filtering, local block page,
    and approved educational resources.
-   Test adult-content and phishing policies independently.
-   **Done when:** both policies work and uncertainty is handled
    clearly.

### Phase 10 --- Accounts and Gemini (optional)

-   Decide if accounts are necessary before implementing authentication.
-   Add secure authentication/minimal profile data if needed.
-   Add optional Gemini only after privacy and key-handling review.
-   **Done when:** optional features fail safely and disclose external
    data use.

### Phase 11 --- Incognito and release review

-   Test incognito with permission on/off, service-worker restart,
    permission denial, and updates.
-   Review permissions, retention, error handling, documentation, and
    limitations.
-   **Done when:** release checklist passes.

## 5. Coding-agent master prompt

Copy the prompt below into your coding agent after opening the existing
TriVex repository.

> You are the senior engineer implementing TriVex, a Chrome Manifest V3
> phishing-protection extension with optional Family Shield.
>
> **Non-negotiable workflow: work on one subsystem at a time, not all
> modules together.** Start by inspecting the repository and existing
> teammate work. Summarize what works, identify the smallest next phase,
> define acceptance tests, and do not modify files until the audit is
> complete.
>
> **Architecture:** JavaScript handles local extension analysis and
> browser protection. Python provides a reference implementation and
> offline evaluation. System A is rule-based; System B is weighted
> scoring; System C compares A/B using documented logic and disagreement
> reporting. Page monitoring and Family Shield are separate modules. LLM
> use is optional and is not automatically machine learning.
>
> **Baseline rules:** System A flags an IP hostname, URL length \>75,
> more than 3 dots in the parsed hostname, `@` or multiple hyphens, or a
> targeted keyword combined with no HTTPS. Keywords: `secure`, `login`,
> `verify`, `update`, `account`, `banking`. System B weights: IP 35,
> suspicious symbols 30, hostname dots \>3 equals 20, keyword 15, length
> \>75 equals 10, no HTTPS 10; threshold 45. Count each feature category
> once unless explicitly documented otherwise.
>
> **Phase order:** (0) repository audit, (1) URL parsing/features, (2)
> System A, (3) System B, (4) System C, (5) popup integration, (6)
> offline evaluation, (7) phishing blocking/local block page, (8)
> bounded page monitoring, (9) Family Shield, (10) optional
> account/Gemini features, (11) incognito/security/release review.
>
> After every phase, stop and report files changed, behavior added,
> tests run/results, limitations, and the next phase. Do not begin the
> next phase until acceptance criteria pass or the user explicitly
> approves proceeding with known failures. Preserve existing teammate
> work and keep `main` runnable.
>
> **Security:** Never claim the extension cannot be disabled, removed,
> or have permissions revoked. Never store plaintext passwords. Do not
> promise encryption without a defined threat model and key lifecycle.
> Never hard-code or commit API keys. Gemini is optional and must
> disclose external data transmission. Do not send browsing URLs/page
> content externally by default. Treat page text as untrusted. Never
> read/store passwords or form values. Minimize permissions, storage,
> and monitoring. Validate redirect targets and use a local block page
> by default. Incognito support requires user opt-in and must not
> silently persist history. "No indicators found" does not mean safe.
>
> **Quality:** Keep JS/Python feature extraction consistent and test
> parity. Use labelled datasets and avoid train/test leakage. Report
> confusion matrix, accuracy, precision, recall, F1, and false-positive
> rate. Never invent results or attribute paper metrics to TriVex. Use
> feature branches, small commits, pull requests, tests, and
> documentation updates.
>
> **First action:** audit the repository and report the current state.
> Do not implement the entire project in one pass.

## 6. Immediate next action

Start at Phase 0, then complete Phase 1 URL parsing and feature
extraction. Do not start account management, Gemini integration, or
Family Shield until the core detector has a stable interface and passing
tests.
