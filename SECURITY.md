# Security Policy

AgentGuard is a security enforcement layer, so vulnerability reports are taken seriously.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/hemanthkumar1012/agentguard/security/advisories/new)
and include:

- affected component (gateway, policy engine, credential broker, audit chain, console)
- steps to reproduce or a proof-of-concept request
- impact (e.g. authorization bypass, credential scope escape, audit tampering)

## In scope

- Authorization or policy bypass
- Credential issuance outside an agent's permissions
- Breaking the SHA-256 audit hash chain without detection
- Authentication, CORS, or rate-limit bypass

## Supported versions

Only the latest commit on `main` receives fixes.
