# PHP2Shell documentation

**Latest public release: [v2.8.0](https://github.com/Opathedane/php2shell/releases/tag/v2.8.0).** Start with the [repository README](../README.md) for download and quick start.

This index is the map of **current** documentation. Historical release gates, PR drafts, and point-in-time audits remain in-tree for provenance but are not the day-to-day user path. Proposed archive moves (not applied yet): [maintainer/DOCS-ARCHIVE-PLAN.md](maintainer/DOCS-ARCHIVE-PLAN.md).

## Authoritative guides

| Topic | Document |
| --- | --- |
| Installation (consultants) | [INSTALL-FOR-CONSULTANTS.md](INSTALL-FOR-CONSULTANTS.md) |
| Platforms & coverage | [SUPPORTED-COVERAGE.md](SUPPORTED-COVERAGE.md) |
| Advanced usage / flags | [ADVANCED-USAGE.md](ADVANCED-USAGE.md) |
| Understanding HTML/CSV reports | [UNDERSTANDING-REPORTS.md](UNDERSTANDING-REPORTS.md) |
| Example report assets | [assets/](assets/) |
| Exit codes & deployment contracts | [EXIT-CODES-AND-DEPLOYMENT.md](EXIT-CODES-AND-DEPLOYMENT.md) |
| Compromise investigation assist | [COMPROMISE-INVESTIGATION.md](COMPROMISE-INVESTIGATION.md) |
| Fleet CSV schema | [CSV-SCHEMA.md](CSV-SCHEMA.md) |
| Windows Server 2012 R2 legacy build | [WINDOWS-LEGACY-2012R2.md](WINDOWS-LEGACY-2012R2.md) |
| Official patch guidance notes | [OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md](OFFICIAL-PHP2SHELL-PATCH-GUIDANCE.md) |
| Threat / IOC rule limitations | [THREAT-INTELLIGENCE.md](THREAT-INTELLIGENCE.md) · [IOC-RULE-LIMITATIONS.md](IOC-RULE-LIMITATIONS.md) |

## Enterprise deployment

| Topic | Document |
| --- | --- |
| Intune | [deployment/INTUNE.md](deployment/INTUNE.md) |
| Group Policy | [deployment/GPO.md](deployment/GPO.md) |
| Report collection | [deployment/REPORT-COLLECTION.md](deployment/REPORT-COLLECTION.md) |
| Signing / Authenticode plans | [deployment/DISTRIBUTION-SIGNING.md](deployment/DISTRIBUTION-SIGNING.md) · [deployment/AUTHENTICODE-IMPLEMENTATION.md](deployment/AUTHENTICODE-IMPLEMENTATION.md) |

## Security, license, governance

| Topic | Document |
| --- | --- |
| Vulnerability disclosure | [../SECURITY.md](../SECURITY.md) |
| Licensing | [LICENSING.md](LICENSING.md) · [../LICENSE](../LICENSE) |
| Contributing | [../CONTRIBUTING.md](../CONTRIBUTING.md) |
| Maintainer governance | [GOVERNANCE.md](GOVERNANCE.md) |
| GitHub About/topics proposal | [maintainer/GITHUB-PRESENTATION-PROPOSAL.md](maintainer/GITHUB-PRESENTATION-PROPOSAL.md) |
| Governance settings checklist (not applied) | [maintainer/MAINTENANCE-GOVERNANCE.md](maintainer/MAINTENANCE-GOVERNANCE.md) |
| Living release checklist | [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) |
| Roadmap | [ROADMAP.md](ROADMAP.md) |

## Release notes

Index: [RELEASE-NOTES.md](RELEASE-NOTES.md). Version bodies: [releases/](releases/) (used as GitHub Release notes).

## Design (maintainers)

| Topic | Document |
| --- | --- |
| nginx / PHP-FPM discovery | [design/nginx-fpm-discovery.md](design/nginx-fpm-discovery.md) |
| LIVE_DOCKER validation | [design/nginx-fpm-integration-validation.md](design/nginx-fpm-integration-validation.md) |
| v2.8.0 readiness evidence | [releases/v2.8.0-readiness.md](releases/v2.8.0-readiness.md) · [pr-assets/v2.8.0-nginx-fpm-live/](pr-assets/v2.8.0-nginx-fpm-live/) |

## Historical / process artifacts (not primary user docs)

Per-version finalize checklists (`RELEASE-FINALIZE-CHECKLIST-*.md`), enterprise QA gates (`*-2.7.2.md`, `AUDIT-PRODUCTION-READINESS-*.md`), PR drafts (`pr-draft-*.md`), and presentation memos (`GITHUB-PRESENTATION.md`, `PROJECT-PRESENTATION.md`, `*-2026-10-21.md`) are retained for audit trail. Prefer the living [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) and [GOVERNANCE.md](GOVERNANCE.md) for current process. Archive proposal: [maintainer/DOCS-ARCHIVE-PLAN.md](maintainer/DOCS-ARCHIVE-PLAN.md).
