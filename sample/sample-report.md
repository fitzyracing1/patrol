# Patrol report

_Static, defensive, owner-only scan. No live-service traffic, no auth attempts, no exploits._

| Repo | SECURITY.md | Vuln deps | Secrets | Risky workflow findings | Dependabot | CodeQL |
|---|---|---|---|---|---|---|
| fitzyracing1/Super | missing | 0 | 0 | 1 | off | off |
| fitzyracing1/fakegreen | missing | 0 | 0 | 0 | off | off |
| fitzyracing1/DIS | missing | 0 | 0 | 0 | off | off |
| fitzyracing1/phone-robot | missing | 0 | 2 | 0 | off | off |
| fitzyracing1/amalia2.0 | missing | 0 | 0 | 0 | off | off |

## fitzyracing1/Super
- Consent signals: SECURITY.md=none, security.txt=none, bounty reference=False
- Dependabot open alerts: n/a
  - note: dependabot alerts unavailable: gh: Dependabot alerts are disabled for this repository. (HTTP 403)
gh: This API operation needs the "admin:repo_hook" scope. To request it, run:  gh auth refresh -h github.com -s admin:repo_hook
- Secrets (redacted): 0
- Workflow findings: 1
  - [medium] .github/workflows/ci.yml: no permissions block (inherits repo default token scope)
- Dependabot alerts: off; dependabot.yml: no; CodeQL: off

## fitzyracing1/fakegreen
- Consent signals: SECURITY.md=none, security.txt=none, bounty reference=False
- Dependabot open alerts: n/a
  - note: dependabot alerts unavailable: gh: Dependabot alerts are disabled for this repository. (HTTP 403)
gh: This API operation needs the "admin:repo_hook" scope. To request it, run:  gh auth refresh -h github.com -s admin:repo_hook
- Secrets (redacted): 0
- Workflow findings: 0
- Dependabot alerts: off; dependabot.yml: no; CodeQL: off

## fitzyracing1/DIS
- Consent signals: SECURITY.md=none, security.txt=none, bounty reference=False
- Dependabot open alerts: n/a
  - note: dependabot alerts unavailable: gh: Dependabot alerts are disabled for this repository. (HTTP 403)
gh: This API operation needs the "admin:repo_hook" scope. To request it, run:  gh auth refresh -h github.com -s admin:repo_hook
- Secrets (redacted): 0
- Workflow findings: 0
- Dependabot alerts: off; dependabot.yml: no; CodeQL: off

## fitzyracing1/phone-robot
- Consent signals: SECURITY.md=none, security.txt=none, bounty reference=False
- Dependabot open alerts: n/a
  - note: dependabot alerts unavailable: gh: Dependabot alerts are disabled for this repository. (HTTP 403)
gh: This API operation needs the "admin:repo_hook" scope. To request it, run:  gh auth refresh -h github.com -s admin:repo_hook
- Secrets (redacted): 2
  - generic_assignment at server/test/helpers.mjs:12 (TOKE…33)
  - generic_assignment at server/test/server.test.mjs:11 (TOKE…33)
- Workflow findings: 0
- Dependabot alerts: off; dependabot.yml: no; CodeQL: off

## fitzyracing1/amalia2.0
- Consent signals: SECURITY.md=none, security.txt=none, bounty reference=False
- Dependabot open alerts: n/a
  - note: dependabot alerts unavailable: gh: Dependabot alerts are disabled for this repository. (HTTP 403)
gh: This API operation needs the "admin:repo_hook" scope. To request it, run:  gh auth refresh -h github.com -s admin:repo_hook
- Secrets (redacted): 0
- Workflow findings: 0
- Dependabot alerts: off; dependabot.yml: no; CodeQL: off
