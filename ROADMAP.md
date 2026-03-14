# VibeScanner Roadmap

## Phase 1: Detection Accuracy
- Expand SQL injection coverage from error-based checks to hybrid detection:
  - error-based
  - boolean-based
  - time-based
- Add richer evidence for each finding:
  - detection method
  - confidence level
  - response diff indicators
- Add better XSS context handling:
  - HTML body
  - attribute
  - script block
  - DOM-based flows

## Phase 2: Crawling and Session Reliability
- Improve crawler normalization and duplicate handling.
- Support authenticated scans more reliably:
  - CSRF token refresh
  - cookie persistence
  - saved login profiles
- Add retries, rate limits, and resumable scans.

## Phase 3: Professional Reporting
- Store evidence and confidence in the database.
- Add CWE, OWASP, and remediation guidance to findings.
- Export results in JSON, CSV, PDF, HTML, and SARIF.

## Phase 4: Testing and Quality
- Add repeatable regression tests against intentionally vulnerable targets.
- Add smoke tests for:
  - reflected XSS
  - stored XSS
  - error-based SQLi
  - boolean-based SQLi
  - time-based SQLi
- Add benchmark scans so performance regressions are visible.

## Phase 5: Product Polish
- Add scan policies such as `quick`, `balanced`, and `deep`.
- Add a CLI mode for automation and CI usage.
- Add plugin hooks so new checks do not all live in one file.
