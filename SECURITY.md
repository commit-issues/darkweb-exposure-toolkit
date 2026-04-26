# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (main) | ✅ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in this project, report it privately:

1. Go to the **Security** tab on this repository
2. Click **"Report a vulnerability"**
3. Fill out the private disclosure form

### What to include
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### What to expect
- Acknowledgment within 48 hours
- Assessment and response within 7 days
- Credit in release notes if desired

## Scope

This tool is a personal data exposure monitor. It uses public APIs only
and stores all data locally. It does not access dark web resources,
private data, or any unauthorized systems.

In scope:
- Vulnerabilities in the Python source code
- Dependency vulnerabilities
- Privacy leaks or unintended data transmission
- .env or credential exposure risks

Out of scope:
- Bugs or vulnerabilities within third-party APIs themselves
  (HIBP, GitHub API) — report those directly to their respective teams.
  However, if our integration with them causes a privacy or security
  issue, that IS in scope — please report it.
- Issues requiring physical access to a user's machine

---

*Security first. Privacy always.*
*Built by [SudoCode](https://github.com/commit-issues)*
