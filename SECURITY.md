# Security Policy

## Scope

This repository contains the API auditing tool, not ASGARD production source code or credentials.

## Sensitive information

Never commit or emit in generated artifacts:

- access tokens;
- API keys;
- passwords;
- private keys;
- session identifiers;
- production secrets;
- credential-bearing connection strings;
- confidential source code copied from audited repositories;
- customer or personal data.

When a detector encounters a secret-like value, it must record only the authentication/credential mechanism and redact the value.

## Audit access

Audited repositories should be accessed with the minimum permissions required, preferably read-only.

## Generated artifacts

Generated outputs must be treated according to the sensitivity of the audited repository. Security findings from private ASGARD repositories must not be published in this public tool repository.

## Failure behavior

If redaction cannot be guaranteed for a candidate artifact, publication must fail closed. A failed candidate must not replace the previous valid audit.

## Reporting

Report vulnerabilities privately to the repository owner. Do not create public issues containing ASGARD secrets, private source excerpts or customer information.
