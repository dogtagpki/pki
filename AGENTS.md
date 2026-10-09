# AGENTS.md: Dogtag PKI

Instructions for AI coding agents working in this repository.
Human contributors: see the [AI-Assisted Design & Development
Guidelines](https://github.com/dogtagpki/pki/wiki/AI-Assisted-Design-and-Development-Guidelines)
on the Dogtag PKI wiki for the full design and review process.

## About this repo

Dogtag PKI is the Certificate Authority suite (Java services plus Python CLI).
Runs as webapps in Tomcat; uses JSS for crypto and TLS, backed by NSS.

Subsystems (`base/`): ca, kra, ocsp, tks, tps, acme, est.

## Build & test

Build RPMs:

    ./build.sh rpm        # output: ~/build/pki/

Prerequisites (Fedora):

    # pick the COPR matching your branch: @pki/master, or
    # @pki/<major> / @pki/<major>.<minor> for a release branch
    sudo dnf copr -y enable @pki/master
    sudo dnf builddep -y --spec pki.spec

Tests: CI workflows in `.github/workflows/` (per-subsystem: `ca-tests.yml`,
`kra-tests.yml`, and so on; `python-tests.yml`). Local test framework: `tests/dogtag/`.

## Commit conventions

See CONTRIBUTING.md ("Git Commit Messages"): imperative mood,
subject < 50 chars, body wrapped at 72.

## Writing style (docs, comments, commit messages)

Avoid em dashes (—); they read as AI-written. When removing one, replace it
with the punctuation that fits the role it played, not reflexively a hyphen:

- Paired aside (an em dash on each side of an inserted phrase): use commas or
  parentheses, not two hyphens.
- Introducing an explanation, expansion, or list: use a colon.
- Break between two independent clauses: use a period or semicolon.
- Simple separator (e.g. in a heading or label): a single hyphen (-) or en
  dash (–) is fine.

Do not type `---`, which some Markdown and AsciiDoc renderers convert into an
em dash.

Prefer plain ASCII. Replace typographic characters with ASCII equivalents:
curly quotes with straight quotes, ellipsis (…) with `...`, arrows (→) with
`->`. The section sign `§` is fine for standards references (e.g. RFC 8659 §3).

Prefer prose or simple bullet lists. Use a pipe `|` table only for genuinely
tabular data (a grid of comparable values), not for layout or emphasis.

The goal is prose that reads as human-written, not mechanically processed.

## AI-assisted design and development

AI assistance is standard but disciplined: the assignee reviews every
AI-generated change and runs the necessary developer testing. Standard
design and code reviews still apply.

When a human asks you to:

- **Estimate feature effort**: assume AI-assisted design and development
  exercised with caution (assignee reviews all generated changes; standard
  design and code reviews followed). Give each estimate as a range, list testing effort
  separately, and name the top one or two unknowns that could push it higher.
  Where it helps, break the work into phases and estimate each (for example,
  a Technology Preview first, then one or more follow-on releases up to a
  fully supported (GA) version).

- **Summarize a session for a design doc or PR**: produce a short bullet
  list of what was asked for and the decisions that shaped the final result;
  keep it brief and include only what actually shaped the outcome. Flag
  anything security- or standards-related separately. For a PR, put this in
  the git commit message body (below the subject line); for a multi-commit
  PR, the PR description is fine.

Always, without being asked:

- **Flag security-sensitive changes**: when your work touches cert/key
  handling, authentication, authorization, trust evaluation, input
  validation, crypto, or RFC/standards compliance, call it out explicitly
  and flag for extra review.

## Process (humans)

New features follow: investigation report -> design review -> implementation
-> code review. Design docs and PRs carry a brief "Intent & Rationale"
summary (see above). Full process: see the [AI-Assisted Design & Development
Guidelines](https://github.com/dogtagpki/pki/wiki/AI-Assisted-Design-and-Development-Guidelines)
on the Dogtag PKI wiki.
