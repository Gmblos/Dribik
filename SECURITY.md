# Security policy

## Supported versions

| Version | Support |
| --- | --- |
| 0.0.1-beta | Active |

## Using Skillet

Skillet is for **authorized** assessment only. Loading third-party hosts you do not have permission to test is misuse of the tool and may be illegal.

## Reporting vulnerabilities in Skillet itself

If you find a security issue **in this repository** (for example path traversal when writing reports, or a bypass of scope checks), email the maintainers privately or open a GitHub Security Advisory. Do not file a public issue with a working exploit.

We will acknowledge reports that include:

- Affected version
- Impact (integrity of scope gates, secret leakage, unexpected file writes)
- Minimal steps to reproduce **without** targeting third-party systems

## Secrets

Never commit `.env` files, API keys, session cookies, or customer graphs.
