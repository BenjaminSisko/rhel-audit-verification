---
type: reference
status: release-candidate
owner: Product documentation / Wren Adler
last_verified: 2026-09-23
review_on: next app release
---

# Screenshot index and provenance

These are actual browser captures from the 1.5.1 Express integration walkthrough
on Splunk Enterprise 10.4.3, captured September 23, 2026. The isolated app is
labeled **RHEL Audit Express TEST**. No synthetic source events were indexed
for these pictures. The normal downloadable installer has no TEST suffix.

Private host/index names, identities and source details are masked gray at
capture time. Sensitive table cells are obscured with capture-only CSS so masks
do not cover neighboring tiles. The underlying counts and status text are not
replaced. No credentials, session cookies, source logs or unredacted originals
are included. Visual inspection and a supplementary known-marker OCR check
were performed; neither is an independent security approval.

| Picture | Purpose |
|---|---|
| [01 — Upload form](images/01-install-upload.png) | File selection and Upgrade app option. |
| [01b — Installation notice](images/01b-install-notice.png) | Actual restart-required message; no server restart was performed. |
| [02 — First launch](images/02-first-launch.png) | Continue to app setup page. |
| [03 — Full setup page](images/03-express-start.png) | Express/Advanced entry points and overall layout. |
| [04 — Discover feeds](images/04-find-logs.png) | Recognized suggestions and an unrecognized/mixed feed. |
| [05 — Review selection](images/05-review-selection.png) | Preserved inventory, confirmation and Finish and check. |
| [06 — Setup results](images/06-setup-results.png) | Sample cap and missing-content warning remain visible. |
| [07 — Restore settings](images/07-restore-settings.png) | No-ID restore after reload. |
| [08 — Narrow viewport inspection](images/08-express-mobile.png) | Desktop layout in a narrow viewport; Splunk's outer page can retain a minimum width. Not mobile certification. |
| [09 — Review filters](images/09-dashboard-filters.png) | Time, host, application and Submit. |
| [10 — Authentication tiles](images/10-authentication-tiles.png) | Successful/failed sign-in and successful sign-out separately. |
| [11 — Event sample](images/11-event-sample.png) | Latest sample headings and content/verification status. |
| [12 — Feed readiness](images/12-review-readiness.png) | Expected-feed count and an observed feed's status. |

Image bytes are covered by the release's `MANIFEST.json`. No invented screen
mockups or AI-generated product screenshots are used. Captured values are
time-bound test observations, not promises of event counts or complete coverage.

Read next: [install with Express](EXPRESS-INSTALL.md), then [review events](USING-THE-APP.md).
