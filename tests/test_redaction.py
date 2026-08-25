import unittest

from asgard_api_auditor.redaction import contains_unredacted_secret_like_value, redact_text


class RedactionTests(unittest.TestCase):
    def test_redacts_bearer_token(self) -> None:
        value = "Authorization: Bearer super-secret-token"
        redacted = redact_text(value)
        self.assertIn("Bearer [REDACTED]", redacted)
        self.assertNotIn("super-secret-token", redacted)
        self.assertFalse(contains_unredacted_secret_like_value(redacted))

    def test_redacts_password_in_connection_string(self) -> None:
        value = "mysql://user:password123@db.internal/app"
        redacted = redact_text(value)
        self.assertIn("user:[REDACTED]@", redacted)
        self.assertNotIn("password123", redacted)

    def test_redacts_secret_query_parameter(self) -> None:
        value = "https://service/api?token=abc123&x=1"
        redacted = redact_text(value)
        self.assertIn("token=[REDACTED]", redacted)
        self.assertNotIn("abc123", redacted)


if __name__ == "__main__":
    unittest.main()
