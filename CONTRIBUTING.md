# Contributing to Hush Relay

Contributions to documentation, tests, interoperability and security hardening are welcome.

## Before opening a pull request

1. Review the project [scope and limitations](ABOUT.md) and [security policy](SECURITY.md).
2. Keep changes focused and describe the threat model, behavior or bug being addressed.
3. Prefer minimal changes to the no-build, WebCrypto + PHP architecture unless a change is justified.
4. Run `./tests/run.sh` (requires PHP, Node.js 20+, curl and a shell). For UI changes, also run `./tests/run.sh --e2e` after installing the Python Playwright package and Chromium.
5. Include tests for regressions, malformed inputs, network failure and replay or authentication failure paths where relevant.
6. Do not add analytics, tracking or telemetry by default. Avoid committing credentials, recovery words, private keys or relay mailbox data.
7. Explain new dependencies and include their upstream license and attribution notices.

## Vulnerability reporting

Do **not** post exploit details or sensitive vulnerabilities in public issues or pull requests. Use GitHub's **Report a vulnerability** feature under the repository Security tab. See [SECURITY.md](SECURITY.md) for scope and reporting details.

## Licensing submissions

By submitting a contribution, you agree to make your contribution available under the existing project license, **AGPL-3.0-or-later**, and confirm that you are authorized to submit it. This does not assign your copyright to the project owner. Third-party contributions must be compatible with the project license and must retain required notices.

## Maintainer review

A passing automated test suite alone does not establish cryptographic security. Changes to encryption, identity, relay authorization, recovery or device linking require adversarial review and careful interoperability testing before release.
