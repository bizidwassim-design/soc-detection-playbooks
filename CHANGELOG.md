# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `SECURITY.md` with a private vulnerability-reporting process and the project's security commitments.
- Continuous integration on every push and pull request (see `.github/workflows/`).
- Dependabot for GitHub Actions versions.
- This changelog.
- Three rules closing the kill-chain gaps: `discovery/ad_enumeration_from_workstation.yml`, `command_and_control/powershell_download_cradle.yml`, `exfiltration/cloud_sync_tool_execution.yml` (14 rules total) and the `playbooks/data-exfiltration.md` playbook.
- CI converts a sample rule with the Splunk backend and fails if the Navigator layer is stale.

## [1.0.0] — 2026-10-31

### Added
- Initial public release.
