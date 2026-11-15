# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**. Do not open a public
issue or pull request for a security problem.

Include the affected version or commit, how to reproduce it, and the impact
you expect. You should get a first answer within a week.

In scope, for example: reaching ports or hosts an identity was not granted,
bypassing admin authentication or CSRF checks, leaking UUIDs, tokens or
private keys, and a direct connection that bypasses sing-box.

## Supported versions

Only the latest commit on `main` receives fixes.

## Deployment notes

- Hand pairing output (`secrets/`, `app.json`) over through trusted channels
  only; it contains credentials.
- Keep the config directory at 0700 and its files at 0600.
- Set an admin password of at least 16 characters right after the first login.
- Never turn off certificate verification or expose loopback mappings on
  `0.0.0.0` to work around connection problems.
