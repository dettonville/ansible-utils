import unittest

from ansible_collections.dettonville.utils.plugins.module_utils.utils import (
    matches_key,
    redact_sensitive_values_from_object,
)


class TestUtilsKeyMatchingAndRedaction(unittest.TestCase):
    def test_matches_key_basic(self):
        # Verify standard sensitive keys match
        self.assertTrue(
            matches_key("password", ["password", "token", "secret"])
        )
        self.assertTrue(matches_key("api_key", [r".*key.*"]))

        # Verify compound words like 'keycloak' do not falsely trigger
        # general 'key' patterns
        self.assertFalse(matches_key("keycloak", ["key"]))
        self.assertFalse(matches_key("keycloak_url", ["key"]))
        self.assertTrue(matches_key("keycloak_password", ["password"]))

    def test_redact_sensitive_values_from_object(self):
        data = {
            "app_name": "my-service",
            "keycloak": {
                "realm": "master",
                "client_secret": "super-secret-value",
            },
            "database": {
                "user": "admin",
                "password": "db-secret-password",
            },
            "tokens": ["token1", "token2"],
        }

        key_patterns = ["password", "secret", "token"]
        redacted_data = redact_sensitive_values_from_object(data, key_patterns)

        # Non-sensitive / compound keys should remain untouched
        self.assertEqual(redacted_data["app_name"], "my-service")
        self.assertEqual(redacted_data["keycloak"]["realm"], "master")
        self.assertEqual(redacted_data["database"]["user"], "admin")

        # Keycloak configuration container itself is preserved, but
        # inner secrets are redacted
        self.assertIsInstance(redacted_data["keycloak"], dict)
        self.assertEqual(
            redacted_data["keycloak"]["client_secret"], "<redacted>"
        )

        # Sensitive keys should be redacted
        self.assertEqual(redacted_data["database"]["password"], "<redacted>")


if __name__ == "__main__":
    unittest.main()
