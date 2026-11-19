# Changelog

All notable changes to GrokSwitch are documented here.

## [0.5.0] - 2026-11-19

- Add `grok-switch refresh` (alias `refresh-tokens`) to renew saved xAI OIDC credentials via `https://auth.x.ai/oauth2/token` while respecting `auth.json.lock` and session locks.
- Automatically and silently refresh expired or HTTP 401 xAI OIDC accounts during `grok-switch list` (when not `--offline`), updating snapshots and registry metadata without disturbing active Grok sessions.
- Sync stale snapshots from live active `auth.json` when refreshing an already-valid active account.
- Maintain repository at `github.com/JasonJarvan/GrokSwitch` under the MIT license.

## [0.4.1] - 2026-08-12

- Simplify project descriptions and usage documentation.

## [0.4.0] - 2026-08-12

Initial public release.

- Save, import, rename, remove, and switch Grok Build accounts.
- Return to the previous account or run another account in an isolated process.
- Import native `auth.json` files and convert CPA xAI OAuth files locally.
- Display each account's live subscription Tier, remaining quota, and reset time.
- Support macOS, Linux, and Windows on amd64 and arm64.

[0.5.0]: https://github.com/JasonJarvan/GrokSwitch/releases/tag/v0.5.0
[0.4.1]: https://github.com/JasonJarvan/GrokSwitch/releases/tag/v0.4.1
[0.4.0]: https://github.com/JasonJarvan/GrokSwitch/releases/tag/v0.4.0
