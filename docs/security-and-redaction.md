# Security and Redaction

## Principle

The auditor needs enough source context to discover API contracts, but generated knowledge must not become a secret exfiltration mechanism.

## Values that must be redacted

At minimum:

- bearer/basic credentials;
- API keys/tokens;
- passwords;
- private keys;
- cookies/session IDs;
- credential-bearing connection strings;
- secret query parameters;
- customer/personal data examples when not required for the contract.

## What may be retained

Retain the mechanism, not the value. Example:

```text
Authorization: Bearer [REDACTED]
```

or:

```text
authentication: bearer_token
```

## Fail closed

If a generated candidate cannot be safely redacted, the publication step must fail. The previous valid audit remains untouched.

## Evidence discipline

Prefer file/line/function references and structural summaries over copying source code into artifacts.
