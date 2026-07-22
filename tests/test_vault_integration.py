from __future__ import annotations

import json
import os
import unittest
import urllib.request
from unittest.mock import patch

from verdikt.secrets import SecretBrokerError, read_vault_secret


VAULT_ADDR = os.getenv("VERDIKT_TEST_VAULT_ADDR", "")
VAULT_TOKEN = os.getenv("VERDIKT_TEST_VAULT_TOKEN", "")


@unittest.skipUnless(
    VAULT_ADDR and VAULT_TOKEN,
    "real Vault integration URL and token are not configured",
)
class RealVaultIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        request = urllib.request.Request(
            VAULT_ADDR.rstrip("/") + "/v1/secret/data/verdikt/integration",
            data=json.dumps(
                {"data": {"api_token": "real-vault-integration-secret"}}
            ).encode(),
            headers={
                "Content-Type": "application/json",
                "X-Vault-Token": VAULT_TOKEN,
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertIn(response.status, {200, 204})

    def test_reads_secret_from_real_vault_kv_v2(self) -> None:
        with patch.dict(
            os.environ,
            {
                "VERDIKT_VAULT_ADDR": VAULT_ADDR,
                "VERDIKT_VAULT_TOKEN": VAULT_TOKEN,
                "VERDIKT_SECRET_TIMEOUT_SECONDS": "2",
            },
            clear=True,
        ):
            value = read_vault_secret(
                "secret/data/verdikt/integration",
                "api_token",
            )

        self.assertEqual(value, "real-vault-integration-secret")

    def test_real_vault_missing_path_is_normalized(self) -> None:
        with patch.dict(
            os.environ,
            {
                "VERDIKT_VAULT_ADDR": VAULT_ADDR,
                "VERDIKT_VAULT_TOKEN": VAULT_TOKEN,
            },
            clear=True,
        ), self.assertRaisesRegex(SecretBrokerError, "Vault returned HTTP 404"):
            read_vault_secret(
                "secret/data/verdikt/does-not-exist",
                "api_token",
            )


if __name__ == "__main__":
    unittest.main()
