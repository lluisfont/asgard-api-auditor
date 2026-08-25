# Security Policy

## Scope

This repository contains the API auditing tool, not ASGARD production source code or credentials.

## Sensitive information

Never commit or emit in generated artifacts:

- access tokens;
- API keys;
- passwords;
- private keys;
- production secrets;
- connection strings containing credentials;
- confidential source code copied from audited repositories;
- customer data.

When a detector encounters a secret-like value, it must record only that a credential mechanism exists and redact the value.

## Repository access

Audited repositories should be accessed with the minimum permissions required, preferably read-only for audit execution.

## Reporting

Security findings discovered while auditing ASGARD repositories belong in the private audit output and must not be published in this public repository.
