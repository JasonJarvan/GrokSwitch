# Security Policy

GrokSwitch manages login credentials, so security reports should not include a
real `auth.json`, CPA file, access token, refresh token, ID token, or an archive
of `~/.grok/accounts`.

## Supported versions

Only the latest published release is supported with security fixes.

## Reporting a vulnerability

Please use the repository's
[private vulnerability reporting](https://github.com/bbbkawaii/GrokSwitch/security/advisories/new)
page. Include the affected command, operating system, Grok Build version, and a
minimal reproduction that uses redacted or synthetic credentials.

Do not open a public issue for a vulnerability that could expose credentials or
allow one local account to overwrite another account's authentication state.
