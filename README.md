# Patrol

A **defensive, consent-based, static-only** security scanner for GitHub repos.

## What it checks
- Missing `SECURITY.md` (and other consent signals: `.well-known/security.txt`, bug-bounty references)
- Vulnerable dependencies (Dependabot alerts via read-only `gh api`; `npm audit --package-lock-only` when a lockfile exists)
- Committed secrets (regex pass, values redacted in reports)
- Risky GitHub Actions workflows (no `permissions:` block, `write-all`, `pull_request_target`, untrusted-text expression injection)
- Whether Dependabot alerts and CodeQL are enabled

## Design: defensive only
- **Static only.** Shallow clone + read-only API calls. Never traffic at a live service, never auth attempts, never exploits.
- **Owner-only in v1.** `ALLOWED_OWNERS = {"fitzyracing1"}` is hard-coded; any other owner is refused before anything is touched.
- **Consent-first for the future.** Patrol records whether a repo *invites* reports (SECURITY.md / security.txt / bounty program). Outside scanning will require that signal; v1 just reports it.
- **Writes nothing remotely.** No issues, no comments, no pushes. Output is local Markdown + JSON.

## Lit / dark ethos
Status is lit or dark, nothing else. CI is lit when every test passes, dark when anything fails. A finding is a thing to fix, not a score.

## Usage
```
python3 -m patrol Super fakegreen DIS -o patrol-out
```
Zero dependencies beyond Python 3.9+ and a signed-in `gh` CLI. See `sample/sample-report.md`.

## License
MIT © 2026 Joshua Almeida

## Plans

This project is free, and its license stays as is. Support it through [GitHub Sponsors](https://github.com/sponsors/fitzyracing1):

- **Free**: use the code, community support.
- **Pro ($49/month)**: priority issues and support.
- **Team ($199/month)**: priority support for your team plus early access.
