# Copyright 2022 Canonical Ltd
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


import copy
import hashlib
import json
import os
import pathlib
import tempfile
from datetime import datetime, timedelta, timezone
from unittest import TestCase, mock

import ops
from jose.backends.cryptography_backend import CryptographyRSAKey
from jose.constants import Algorithms
from ops.model import ActiveStatus, BlockedStatus, SecretNotFoundError, WaitingStatus
from ops.testing import ActionFailed, Harness

from src.charm import (
    HOST_KEY_LOOKUP,
    JIMM_SERVICE_NAME,
    JWKS_ACTIVATE_AT_LOOKUP,
    JWKS_EXPIRES_AT_LOOKUP,
    JWKS_KID_LOOKUP,
    JWKS_PATH,
    JWKS_PRE_ROTATION_INTERVAL,
    JWKS_PRIVATE_KEY_LOOKUP,
    JWKS_PRIVATE_KEY_PATH,
    JWKS_PROPAGATION_DELAY,
    JWKS_PUBLIC_JWK_LOOKUP,
    JWKS_ROTATION_PERIOD,
    JWKS_SECRET_LABELS,
    SESSION_KEY_LOOKUP,
    TRUSTED_CA_PATH,
    WORKLOAD_CONTAINER,
    JimmOperatorCharm,
    is_valid_private_key,
    new_host_key,
    new_jwks_secret,
    new_session_key,
)

OAUTH_CLIENT_ID = "jimm_client_id"
OAUTH_CLIENT_SECRET = "test-secret"
OAUTH_PROVIDER_INFO = {
    "authorization_endpoint": "https://example.oidc.com/oauth2/auth",
    "introspection_endpoint": "https://example.oidc.com/admin/oauth2/introspect",
    "issuer_url": "https://example.oidc.com",
    "jwks_endpoint": "https://example.oidc.com/.well-known/jwks.json",
    "scope": "email offline_access openid profile",
    "token_endpoint": "https://example.oidc.com/oauth2/token",
    "userinfo_endpoint": "https://example.oidc.com/userinfo",
}

OPENFGA_PROVIDER_INFO = {
    "http_api_url": "http://openfga.localhost:8080",
    "grpc_api_url": "grpc://openfga.localhost:8090",
    "store_id": "fake-store-id",
    "token": "fake-token",
}

MINIMAL_CONFIG = {
    "uuid": "1234567890",
    "dns-name": "jimm.localhost",
    "public-key": "izcYsQy3TePp6bLjqOo3IRPFvkQd2IKtyODGqC6SdFk=",
    "private-key": "ly/dzsI9Nt/4JxUILQeAX79qZ4mygDiuYGqc2ZEiDEc=",
}

fixed_host_key = new_host_key()[HOST_KEY_LOOKUP]
TEST_JWKS_PRIVATE_KEY_1 = "-----BEGIN RSA PRIVATE KEY-----\nkey-1\n-----END RSA PRIVATE KEY-----\n"
TEST_JWKS_PRIVATE_KEY_2 = "-----BEGIN RSA PRIVATE KEY-----\nkey-2\n-----END RSA PRIVATE KEY-----\n"
TEST_JWKS_PUBLIC_1 = {
    "alg": "RS256",
    "e": "AQAB",
    "kid": "00000000-0000-0000-0000-000000000001",
    "kty": "RSA",
    "n": "test-modulus-1",
    "use": "sig",
}
TEST_JWKS_PUBLIC_2 = {
    "alg": "RS256",
    "e": "AQAB",
    "kid": "00000000-0000-0000-0000-000000000002",
    "kty": "RSA",
    "n": "test-modulus-2",
    "use": "sig",
}
TEST_JWKS_PRIVATE_KEY_3 = "-----BEGIN RSA PRIVATE KEY-----\nkey-3\n-----END RSA PRIVATE KEY-----\n"
TEST_JWKS_PUBLIC_3 = {
    "alg": "RS256",
    "e": "AQAB",
    "kid": "00000000-0000-0000-0000-000000000003",
    "kty": "RSA",
    "n": "test-modulus-3",
    "use": "sig",
}

BASE_ENV = {
    "BAKERY_PRIVATE_KEY": "ly/dzsI9Nt/4JxUILQeAX79qZ4mygDiuYGqc2ZEiDEc=",
    "BAKERY_PUBLIC_KEY": "izcYsQy3TePp6bLjqOo3IRPFvkQd2IKtyODGqC6SdFk=",
    "JIMM_ACCESS_TOKEN_EXPIRY_DURATION": "6h",
    "JIMM_AUDIT_LOG_RETENTION_PERIOD_IN_DAYS": "0",
    "JIMM_BOOTSTRAP_LOGIN_TOKEN_REFRESH_URL": "https://jimm.localhost/.well-known/jwks.json",
    "JIMM_DASHBOARD_FINAL_REDIRECT_URL": "https://jaas.ai/models",
    "JIMM_DASHBOARD_LOCATION": "https://jaas.ai/models",
    "JIMM_DNS_NAME": "jimm.localhost",
    "JIMM_DSN": "postgresql://postgres-user:postgres-pass@local-1.localhost/jimm",
    "JIMM_INTERNAL_LISTEN_ADDR": ":9090",
    "JIMM_IS_LEADER": "True",
    "JIMM_JWT_EXPIRY": "5m",
    "JIMM_JWKS_PATH": str(JWKS_PATH),
    "JIMM_JWKS_PRIVATE_KEY_PATH": str(JWKS_PRIVATE_KEY_PATH),
    "JIMM_LISTEN_ADDR": ":8080",
    "JIMM_LOG_LEVEL": "info",
    "JIMM_MACAROON_EXPIRY_DURATION": "24h",
    "JIMM_OAUTH_CLIENT_ID": OAUTH_CLIENT_ID,
    "JIMM_OAUTH_CLIENT_SECRET": OAUTH_CLIENT_SECRET,
    "JIMM_OAUTH_ISSUER_URL": OAUTH_PROVIDER_INFO["issuer_url"],
    "JIMM_OAUTH_SCOPES": OAUTH_PROVIDER_INFO["scope"],
    "JIMM_SECURE_SESSION_COOKIES": True,
    "JIMM_SESSION_COOKIE_MAX_AGE": 86400,
    "JIMM_SESSION_SECRET_KEY": "test-secret",
    "JIMM_SSH_HOST_KEY": fixed_host_key,
    "JIMM_SSH_MAX_CONCURRENT_CONNECTIONS": 100,
    "JIMM_SSH_PORT": 17022,
    "JIMM_UUID": "1234567890",
    "OPENFGA_AUTH_MODEL": 1,
    "OPENFGA_HOST": "openfga.localhost",
    "OPENFGA_PORT": 8080,
    "OPENFGA_SCHEME": "http",
    "OPENFGA_STORE": "fake-store-id",
    "OPENFGA_TOKEN": "fake-token",
}

# The environment may optionally include Vault.
EXPECTED_VAULT_ENV = BASE_ENV.copy()
EXPECTED_VAULT_ENV.update(
    {
        "VAULT_ADDR": "127.0.0.1:8081",
        "VAULT_CACERT_BYTES": "abcd",
        "VAULT_PATH": "charm-juju-jimm-k8s-jimm",
        "VAULT_ROLE_ID": "111",
        "VAULT_ROLE_SECRET_ID": "222",
    }
)


def get_expected_plan(env):
    return {
        "services": {
            JIMM_SERVICE_NAME: {
                "summary": "JAAS Intelligent Model Manager",
                "startup": "disabled",
                "override": "replace",
                "command": "/usr/local/bin/jimmsrv",
                "environment": env,
            }
        },
        "checks": {
            "jimm-check": {
                "override": "replace",
                "period": "1m",
                "http": {"url": "http://localhost:8080/debug/status"},
            }
        },
    }


class TestCharm(TestCase):
    def setUp(self):
        self.maxDiff = None
        self.harness = Harness(JimmOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.disable_hooks()
        self.harness.set_model_name("jimm-model")
        self.harness.add_oci_resource("jimm-image")
        self.harness.set_can_connect("jimm", True)
        self.harness.set_leader(True)
        self.harness.begin()

        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.harness.charm.framework.charm_dir = pathlib.Path(self.tempdir.name)

        jimm_id = self.harness.add_relation("peer", "juju-jimm-k8s")
        self.harness.add_relation_unit(jimm_id, "juju-jimm-k8s/1")
        self.harness.container_pebble_ready("jimm")

        self.ingress_rel_id = self.harness.add_relation("ingress", "nginx-ingress")
        self.harness.add_relation_unit(self.ingress_rel_id, "nginx-ingress/0")

        self.add_oauth_relation()

    # Helper to write the fake OpenFGA model file used by tests
    def _write_openfga_model(self, model: object) -> pathlib.Path:
        root = self.harness.get_filesystem_root(WORKLOAD_CONTAINER)
        dir_path = root / "root" / "openfga"
        dir_path.mkdir(parents=True, exist_ok=True)
        file_path = dir_path / "authorisation_model.json"
        if isinstance(model, str):
            file_path.write_text(model)
        else:
            file_path.write_text(json.dumps(model))
        return file_path

    def use_fake_host_key(self):
        patcher = mock.patch("src.charm.new_host_key", return_value={HOST_KEY_LOOKUP: fixed_host_key})
        patcher.start()
        self.addCleanup(patcher.stop)

    def use_fake_session_secret(self):
        patcher = mock.patch("src.charm.new_session_key", return_value={SESSION_KEY_LOOKUP: "test-secret"})
        self.mock_key = patcher.start()
        self.fake_session_secret_patcher = patcher
        self.addCleanup(patcher.stop)

    def use_fake_jwks_secret(self, jwks_materials=None):
        materials = jwks_materials or [(TEST_JWKS_PUBLIC_1, TEST_JWKS_PRIVATE_KEY_1)]
        iterator = iter(materials)

        def fake_new_jwks_secret(activate_at, expires_at):
            public_jwk, private_key = next(iterator)
            return {
                JWKS_ACTIVATE_AT_LOOKUP: _format_test_datetime(activate_at),
                JWKS_EXPIRES_AT_LOOKUP: _format_test_datetime(expires_at),
                JWKS_KID_LOOKUP: public_jwk["kid"],
                JWKS_PRIVATE_KEY_LOOKUP: private_key,
                JWKS_PUBLIC_JWK_LOOKUP: json.dumps(public_jwk, separators=(",", ":"), sort_keys=True),
            }

        patcher = mock.patch("src.charm.new_jwks_secret", side_effect=fake_new_jwks_secret)
        patcher.start()
        self.addCleanup(patcher.stop)

    def existing_jwks_secrets(self) -> dict[str, ops.Secret]:
        secrets = {}
        for label in JWKS_SECRET_LABELS:
            try:
                secrets[label] = self.harness.model.get_secret(label=label)
            except SecretNotFoundError:
                continue
        return secrets

    def secret_identity(self, secret: ops.Secret):
        return secret.id or secret.get_info().id

    def read_workload_file(self, path: pathlib.Path) -> str:
        root = self.harness.get_filesystem_root(WORKLOAD_CONTAINER)
        return (pathlib.Path(root) / path.relative_to("/")).read_text()

    def use_fake_setup_fga_model(self):
        patcher = mock.patch("src.charm.JimmOperatorCharm.setup_fga_auth_model", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def add_openfga_relation(self):
        self.openfga_rel_id = self.harness.add_relation("openfga", "openfga")
        self.harness.add_relation_unit(self.openfga_rel_id, "openfga/0")
        self.harness.update_relation_data(
            self.openfga_rel_id,
            "openfga",
            {
                **OPENFGA_PROVIDER_INFO,
            },
        )

    def add_vault_relation(self):
        self.harness.charm.on.install.emit()
        id = self.harness.add_relation("vault", "vault-k8s")
        self.harness.add_relation_unit(id, "vault-k8s/0")

        data = self.harness.get_relation_data(id, "juju-jimm-k8s/0")
        self.assertTrue(data)
        self.assertTrue("egress_subnet" in data)
        self.assertTrue("nonce" in data)

        secret_id = self.harness.add_model_secret(
            "vault-k8s/0",
            {"role-id": "111", "role-secret-id": "222"},
        )
        self.harness.grant_secret(secret_id, "juju-jimm-k8s")

        credentials = {data["nonce"]: secret_id}
        self.harness.update_relation_data(
            id,
            "vault-k8s",
            {
                "vault_url": "127.0.0.1:8081",
                "ca_certificate": "abcd",
                "mount": "charm-juju-jimm-k8s-jimm",
                "credentials": json.dumps(credentials, sort_keys=True),
            },
        )

    def add_oauth_relation(self):
        self.oauth_rel_id = self.harness.add_relation("oauth", "hydra")
        self.harness.add_relation_unit(self.oauth_rel_id, "hydra/0")
        secret_id = self.harness.add_model_secret("hydra", {"secret": OAUTH_CLIENT_SECRET})
        self.harness.grant_secret(secret_id, "juju-jimm-k8s")
        self.harness.update_relation_data(
            self.oauth_rel_id,
            "hydra",
            {
                "client_id": OAUTH_CLIENT_ID,
                "client_secret_id": secret_id,
                **OAUTH_PROVIDER_INFO,
            },
        )

    def add_certificate_transfer_relation(self):
        self.receive_ca_rel_id = self.harness.add_relation("receive-ca-cert", "receive-ca-cert")
        self.harness.add_relation_unit(self.receive_ca_rel_id, "receive-ca-cert/0")
        self.harness.update_relation_data(
            self.receive_ca_rel_id,
            "receive-ca-cert",
            {
                "certificates": json.dumps(["cert1", "cert2"]),
            },
        )

    def add_postgres_relation(self):
        self.postgres_rel_id = self.harness.add_relation("database", "postgresql")
        self.harness.add_relation_unit(self.postgres_rel_id, "postgresql/0")
        self.harness.update_relation_data(
            self.postgres_rel_id,
            "postgresql",
            {
                "username": "postgres-user",
                "password": "postgres-pass",
                "endpoints": "local-1.localhost,local-2.localhost",
            },
        )

    def create_auth_model_info(self):
        # Write a minimal model file and set initial state
        self._write_openfga_model("null")
        self.harness.charm._state.openfga_auth_model_hash = "37a6259cc0c1dae299a7866489dff0bd"
        self.harness.charm._state.openfga_auth_model_id = 1

    def ensure_jimm_secrets(self):
        self.harness.enable_hooks()
        self.harness.charm.on.install.emit()

    def start_minimal_jimm(self, jwks_materials=None):
        self.harness.enable_hooks()
        self.use_fake_session_secret()
        self.use_fake_host_key()
        self.use_fake_jwks_secret(jwks_materials)
        self.use_fake_setup_fga_model()
        self.create_auth_model_info()
        self.add_openfga_relation()
        self.add_vault_relation()
        self.add_postgres_relation()
        self.harness.charm.ensure_jwks_secret_key()
        self.harness.update_config(MINIMAL_CONFIG)
        self.assertEqual(self.harness.charm.unit.status.name, ActiveStatus.name)
        self.assertEqual(self.harness.charm.unit.status.message, "running")

    def test_add_certificates_relation(self):
        self.start_minimal_jimm()
        self.harness.set_leader(True)
        self.certificates_rel_id = self.harness.add_relation("certificates", "certificates")
        self.harness.add_relation_unit(self.certificates_rel_id, "certificates/0")
        self.harness.update_relation_data(
            self.certificates_rel_id,
            "certificates",
            {
                "certificates": json.dumps(
                    [
                        {
                            "certificate": "cert",
                            "ca": "ca",
                            "chain": ["chain"],
                            "certificate_signing_request": self.harness.charm._state.csr,
                        }
                    ]
                )
            },
        )
        self.assertEqual(self.harness.charm._state.ca, "ca")
        self.assertEqual(self.harness.charm._state.certificate, "cert")
        self.assertEqual(self.harness.charm._state.chain, ["chain"])

    def test_on_pebble_ready(self):
        self.start_minimal_jimm()

        container = self.harness.model.unit.get_container("jimm")
        # Emit the pebble-ready event for jimm
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        # Check the that the plan was updated
        plan = self.harness.get_container_pebble_plan("jimm")
        self.assertEqual(plan.to_dict(), get_expected_plan(EXPECTED_VAULT_ENV))

    def test_bootstrap_login_token_refresh_url_strips_scheme(self):
        self.harness.enable_hooks()
        self.use_fake_session_secret()
        self.use_fake_host_key()
        self.use_fake_jwks_secret()
        self.use_fake_setup_fga_model()
        self.create_auth_model_info()
        self.add_openfga_relation()
        self.add_vault_relation()
        self.add_postgres_relation()
        self.harness.charm.ensure_jwks_secret_key()

        config_with_scheme = {**MINIMAL_CONFIG, "dns-name": "https://jimm.localhost"}
        self.harness.update_config(config_with_scheme)

        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        plan = self.harness.get_container_pebble_plan("jimm")
        plan_dict = plan.to_dict()
        services = plan_dict.get("services", {})
        service = services.get(JIMM_SERVICE_NAME, {})
        env = service.get("environment", {})
        self.assertEqual(
            env.get("JIMM_BOOTSTRAP_LOGIN_TOKEN_REFRESH_URL"),
            "https://jimm.localhost/.well-known/jwks.json",
        )

    def test_ready_without_plan(self):
        self.harness.enable_hooks()
        self.harness.charm._ready()
        self.assertEqual(self.harness.charm.unit.status.name, BlockedStatus.name)
        self.assertEqual(self.harness.charm.unit.status.message, "Waiting for OAuth relation")

    def test_on_config_changed(self):
        self.start_minimal_jimm()

        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)
        self.harness.update_config(MINIMAL_CONFIG)
        self.harness.set_leader(True)

        # Emit the pebble-ready event for jimm
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        # Check the that the plan was updated
        plan = self.harness.get_container_pebble_plan("jimm")
        self.assertEqual(plan.to_dict(), get_expected_plan(EXPECTED_VAULT_ENV))

    def test_stop(self):
        self.start_minimal_jimm()
        self.harness.charm.on.stop.emit()
        self.assertEqual(self.harness.charm.unit.status.name, WaitingStatus.name)
        self.assertEqual(self.harness.charm.unit.status.message, "stopped")

    def test_update_status(self):
        self.start_minimal_jimm()
        self.harness.charm.on.update_status.emit()
        self.assertEqual(self.harness.charm.unit.status.name, ActiveStatus.name)
        self.assertEqual(self.harness.charm.unit.status.message, "running")

    def test_postgres_relation_joined(self):
        self.harness.enable_hooks()
        self.create_auth_model_info()
        self.add_postgres_relation()
        self.assertEqual(
            self.harness.charm._make_database_dsn(), "postgresql://postgres-user:postgres-pass@local-1.localhost/jimm"
        )

    def test_postgres_secret_storage_config(self):
        self.start_minimal_jimm()

        self.harness.update_config({"postgres-secret-storage": True})
        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        plan = self.harness.get_container_pebble_plan("jimm")
        expected_env = BASE_ENV.copy()
        expected_env.update({"INSECURE_SECRET_STORAGE": "true"})
        self.assertEqual(plan.to_dict(), get_expected_plan(expected_env))

    def test_proxy_settings(
        self,
    ):
        self.start_minimal_jimm()
        os.environ["JUJU_CHARM_NO_PROXY"] = "no-proxy.canonincal.com"
        os.environ["JUJU_CHARM_HTTP_PROXY"] = "http-proxy.canonincal.com"
        os.environ["JUJU_CHARM_HTTPS_PROXY"] = "https-proxy.canonincal.com"
        self.harness.update_config({"postgres-secret-storage": True})
        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        plan = self.harness.get_container_pebble_plan("jimm")
        expected_env = BASE_ENV.copy()
        expected_env.update({"INSECURE_SECRET_STORAGE": "true"})
        expected_env.update({"NO_PROXY": "no-proxy.canonincal.com"})
        expected_env.update({"HTTP_PROXY": "http-proxy.canonincal.com"})
        expected_env.update({"HTTPS_PROXY": "https-proxy.canonincal.com"})
        self.assertEqual(plan.to_dict(), get_expected_plan(expected_env))

        os.environ["JUJU_CHARM_NO_PROXY"] = ""
        os.environ["JUJU_CHARM_HTTP_PROXY"] = ""
        os.environ["JUJU_CHARM_HTTPS_PROXY"] = ""

    def test_dashboard_config(self):
        self.start_minimal_jimm()

        self.harness.update_config(
            {
                **MINIMAL_CONFIG,
                "juju-dashboard-location": "https://some.host",
            }
        )
        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        plan = self.harness.get_container_pebble_plan("jimm")
        expected_values = {
            "JIMM_DASHBOARD_LOCATION": "https://some.host",
            "JIMM_DASHBOARD_FINAL_REDIRECT_URL": "https://some.host",
        }
        plan_dict = plan.to_dict()
        env = plan_dict.get("services", {}).get(JIMM_SERVICE_NAME, {}).get("environment", {})
        self.assertDictEqual(env, env | expected_values)

    def test_oidc_extra_scopes_requested_when_configured(self):
        self.start_minimal_jimm()

        self.harness.update_relation_data(
            self.oauth_rel_id,
            "hydra",
            {
                "scope": "email offline_access openid profile",
            },
        )
        self.harness.update_config({"oauth-optional-scopes": "groups"})

        container = self.harness.model.unit.get_container("jimm")
        with mock.patch("src.charm.logger.warning") as logger_warning:
            self.harness.charm.on.jimm_pebble_ready.emit(container)

        plan = self.harness.get_container_pebble_plan("jimm")
        env = plan.to_dict().get("services", {}).get(JIMM_SERVICE_NAME, {}).get("environment", {})
        self.assertEqual(env["JIMM_OAUTH_SCOPES"], "email groups offline_access openid profile")
        logger_warning.assert_any_call(
            "OAuth provider did not advertise requested OAuth scopes %s; " "JIMM will continue to request them",
            "groups",
        )

    def test_oidc_group_claim_key_rendered_when_configured(self):
        self.start_minimal_jimm()

        self.harness.update_config({"oauth-group-claim-key": "groups"})

        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        plan = self.harness.get_container_pebble_plan("jimm")
        env = plan.to_dict().get("services", {}).get(JIMM_SERVICE_NAME, {}).get("environment", {})
        self.assertEqual(env["JIMM_OAUTH_GROUP_CLAIM_KEY"], "groups")

    def test_oauth_client_credential_scopes_rendered_when_configured(self):
        self.start_minimal_jimm()

        self.harness.update_config({"oauth-client-credential-scopes": "groups profile"})

        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        plan = self.harness.get_container_pebble_plan("jimm")
        env = plan.to_dict().get("services", {}).get(JIMM_SERVICE_NAME, {}).get("environment", {})
        self.assertEqual(env["JIMM_OAUTH_CLIENT_CREDENTIAL_SCOPES"], "groups profile")

    def test_ssh_config(self):
        self.start_minimal_jimm()
        self.harness.update_config(
            {
                **MINIMAL_CONFIG,
                "ssh-port": 22,
                "ssh-max-concurrent-connections": 101,
            }
        )
        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)
        new_plan = self.harness.get_container_pebble_plan("jimm")
        expected_values = {
            "JIMM_SSH_PORT": 22,
            "JIMM_SSH_MAX_CONCURRENT_CONNECTIONS": 101,
        }
        new_plan_dict = new_plan.to_dict()
        new_env = new_plan_dict.get("services", {}).get(JIMM_SERVICE_NAME, {}).get("environment", {})
        self.assertDictEqual(new_env, new_env | expected_values)

    def test_app_dns_address(self):
        self.harness.update_config(MINIMAL_CONFIG)
        self.harness.update_config({"dns-name": "jimm.com"})
        oauth_client = self.harness.charm._oauth_client_config
        self.assertEqual(oauth_client.redirect_uri, "https://jimm.com/auth/callback")

        self.harness.update_config({"dns-name": "jimm.com/some/path"})
        oauth_client = self.harness.charm._oauth_client_config
        self.assertEqual(oauth_client.redirect_uri, "https://jimm.com/some/path/auth/callback")

        self.harness.update_config({"dns-name": "https://jimm.com/"})
        oauth_client = self.harness.charm._oauth_client_config
        self.assertEqual(oauth_client.redirect_uri, "https://jimm.com/auth/callback")

    def test_app_enters_block_states_if_oauth_relation_removed(self):
        self.harness.update_config(MINIMAL_CONFIG)
        self.harness.remove_relation(self.oauth_rel_id)
        container = self.harness.model.unit.get_container("jimm")
        # Emit the pebble-ready event for jimm
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        # Check the that the plan is empty
        plan = self.harness.get_container_pebble_plan("jimm")
        self.assertEqual(plan.to_dict(), {})
        self.assertEqual(self.harness.charm.unit.status.name, BlockedStatus.name)
        self.assertEqual(self.harness.charm.unit.status.message, "Waiting for OAuth relation")

    def test_ssh_ingress_is_published_before_oauth_ready(self):
        self.harness.update_config(MINIMAL_CONFIG)
        self.harness.remove_relation(self.oauth_rel_id)
        container = self.harness.model.unit.get_container("jimm")

        with mock.patch.object(
            self.harness.charm.ingress_ssh,
            "provide_ingress_requirements",
        ) as provide_requirements:
            self.harness.charm.on.jimm_pebble_ready.emit(container)

        provide_requirements.assert_called_once_with(port=self.harness.charm._ssh_port)
        self.assertEqual(self.harness.charm.unit.status.name, BlockedStatus.name)
        self.assertEqual(self.harness.charm.unit.status.message, "Waiting for OAuth relation")

    def test_app_enters_block_state_if_oauth_relation_not_ready(self):
        self.harness.update_config(MINIMAL_CONFIG)
        self.harness.remove_relation(self.oauth_rel_id)
        oauth_relation = self.harness.add_relation("oauth", "hydra")
        self.harness.add_relation_unit(oauth_relation, "hydra/0")
        secret_id = self.harness.add_model_secret("hydra", {"secret": OAUTH_CLIENT_SECRET})
        self.harness.grant_secret(secret_id, "juju-jimm-k8s")
        # If the client-id is empty we should detect that the oauth relation is not ready.
        # The readiness check is handled by the OAuth library.
        self.harness.update_relation_data(
            oauth_relation,
            "hydra",
            {"client_id": ""},
        )
        container = self.harness.model.unit.get_container("jimm")
        # Emit the pebble-ready event for jimm
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        # Check the that the plan is empty
        plan = self.harness.get_container_pebble_plan("jimm")
        self.assertEqual(plan.to_dict(), {})
        self.assertEqual(self.harness.charm.unit.status.name, BlockedStatus.name)
        self.assertEqual(self.harness.charm.unit.status.message, "Waiting for OAuth relation")

    @mock.patch("src.charm.JimmOperatorCharm._jwks_config", return_value=None)
    def test_app_enters_block_state_if_jwks_config_not_ready(self, _mock_jwks_config):
        self.harness.enable_hooks()
        self.use_fake_session_secret()
        self.use_fake_host_key()
        self.use_fake_setup_fga_model()
        self.create_auth_model_info()
        self.add_openfga_relation()
        self.add_vault_relation()
        self.add_postgres_relation()
        self.harness.update_config(MINIMAL_CONFIG)

        plan = self.harness.get_container_pebble_plan("jimm")
        self.assertEqual(plan.to_dict(), {})
        self.assertEqual(self.harness.charm.unit.status.name, BlockedStatus.name)
        self.assertEqual(self.harness.charm.unit.status.message, "Waiting for JWKS secret")

    def test_audit_log_retention_config(self):
        self.start_minimal_jimm()

        self.harness.update_config({"audit-log-retention-period-in-days": "10"})

        # Check the that the plan was updated
        expected_env = EXPECTED_VAULT_ENV.copy()
        expected_env.update({"JIMM_AUDIT_LOG_RETENTION_PERIOD_IN_DAYS": "10"})
        plan = self.harness.get_container_pebble_plan("jimm")
        self.assertEqual(plan.to_dict(), get_expected_plan(expected_env))

    def test_dashboard_relation_joined(self):
        self.start_minimal_jimm()

        id = self.harness.add_relation("dashboard", "juju-dashboard")
        self.harness.add_relation_unit(id, "juju-dashboard/0")
        data = self.harness.get_relation_data(id, "juju-jimm-k8s")

        self.assertTrue(data)
        self.assertEqual(
            data["controller-url"],
            "wss://jimm.localhost",
        )
        self.assertEqual(data["is-juju"], "False")

    def test_dashboard_relation_joined_with_scheme(self):
        self.start_minimal_jimm()

        with mock.patch.object(
            type(self.harness.charm.ingress),
            "url",
            new_callable=mock.PropertyMock,
            return_value="https://jimm.workshop/jimm-jimm",
        ):
            id = self.harness.add_relation("dashboard", "juju-dashboard")
            self.harness.add_relation_unit(id, "juju-dashboard/0")
            data = self.harness.get_relation_data(id, "juju-jimm-k8s")

            self.assertTrue(data)
            self.assertEqual(
                data["controller-url"],
                "wss://jimm.workshop/jimm-jimm",
            )
            self.assertEqual(data["is-juju"], "False")

    def test_vault_relation_joined(self):
        self.start_minimal_jimm()

        plan = self.harness.get_container_pebble_plan("jimm")
        self.assertEqual(plan.to_dict(), get_expected_plan(EXPECTED_VAULT_ENV))

    def test_app_blocked_without_private_key(self):
        self.start_minimal_jimm()

        min_config_no_private_key = MINIMAL_CONFIG.copy()
        min_config_no_private_key["private-key"] = ""
        self.harness.update_config(min_config_no_private_key)
        self.assertEqual(self.harness.charm.unit.status.name, BlockedStatus.name)
        self.assertEqual(
            self.harness.charm.unit.status.message,
            "BAKERY_PRIVATE_KEY configuration value not set: missing private key configuration",
        )

        # Now check that we can get the app into an active state.
        self.harness.update_config(MINIMAL_CONFIG)
        self.assertEqual(self.harness.charm.unit.status.name, ActiveStatus.name)
        self.assertEqual(self.harness.charm.unit.status.message, "running")

    @mock.patch("src.openfga_client.requests.post")
    def test_setup_fga_auth_model(self, mock_post):
        def mocked_requests_post(*args, **kwargs):
            class MockResponse:
                def __init__(self, json_data, status_code):
                    self.json_data = json_data
                    self.status_code = status_code
                    self.ok = True

                def json(self):
                    return self.json_data

            return MockResponse({"authorization_model_id": 123}, 200)

        mock_post.side_effect = mocked_requests_post
        self.harness.enable_hooks()
        # Write a minimal model
        self._write_openfga_model("null")

        self.add_openfga_relation()
        container = self.harness.model.unit.get_container(WORKLOAD_CONTAINER)
        self.harness.charm.setup_fga_auth_model(container)

        # Ensure the authorization model was created and stored
        self.assertEqual(self.harness.charm._state.openfga_auth_model_id, 123)
        self.assertTrue(mock_post.called)

    @mock.patch("src.openfga_client.requests.post")
    @mock.patch("src.openfga_client.requests.get")
    def test_setup_fga_auth_model_skipped_when_auth_model_exists(self, mock_get, mock_post):
        # Prepare the local model file with minimal valid content
        self.harness.enable_hooks()
        auth_model = {"schema_version": "1.1", "type_definitions": []}
        self._write_openfga_model(auth_model)

        # Set an existing model id in state to trigger the comparison path
        self.harness.charm._state.openfga_auth_model_id = "existing-id"

        # Mock GET to return an equivalent remote model
        def mocked_requests_get(*args, **kwargs):
            class MockResponse:
                def __init__(self, json_data, status_code):
                    self.json_data = json_data
                    self.status_code = status_code
                    self.ok = True

                def json(self):
                    return self.json_data

            # Return the remote payload with the same schema and types
            return MockResponse(auth_model, 200)

        mock_get.side_effect = mocked_requests_get

        # Compute the digest of the remote model and set it on state
        remote_digest = hashlib.md5(json.dumps(auth_model, sort_keys=True).encode("utf-8")).hexdigest()
        self.harness.charm._state.openfga_auth_model_digest = remote_digest

        self.add_openfga_relation()
        container = self.harness.model.unit.get_container(WORKLOAD_CONTAINER)
        self.harness.charm.setup_fga_auth_model(container)

        mock_post.assert_not_called()
        # Existing id should remain unchanged
        self.assertEqual(self.harness.charm._state.openfga_auth_model_id, "existing-id")

    @mock.patch("src.openfga_client.requests.post")
    @mock.patch("src.openfga_client.requests.get")
    def test_setup_fga_auth_model_recreated_when_auth_model_changes(self, mock_get, mock_post):
        # Prepare the local model file with minimal valid content
        self.harness.enable_hooks()
        auth_model = {"schema_version": "1.1", "type_definitions": []}
        self._write_openfga_model(auth_model)

        # Set an existing model id in state to trigger the comparison path
        self.harness.charm._state.openfga_auth_model_id = "existing-id"

        # Mock GET to return a remote model
        def mocked_requests_get(*args, **kwargs):
            class MockResponse:
                def __init__(self, json_data, status_code):
                    self.json_data = json_data
                    self.status_code = status_code
                    self.ok = True

                def json(self):
                    return self.json_data

            # Return the remote payload with the same schema and types
            return MockResponse(auth_model, 200)

        mock_get.side_effect = mocked_requests_get

        # Mock POST to return a new model id
        def mocked_requests_post(*args, **kwargs):
            class MockResponse:
                def __init__(self, json_data, status_code):
                    self.json_data = json_data
                    self.status_code = status_code
                    self.ok = True

                def json(self):
                    return self.json_data

            return MockResponse({"authorization_model_id": "new-id"}, 200)

        mock_post.side_effect = mocked_requests_post

        # Set a fake digest that won't match the local model
        # This simulates a change in the model that requires recreation
        self.harness.charm._state.openfga_auth_model_digest = "fake-digest"

        self.add_openfga_relation()
        container = self.harness.model.unit.get_container(WORKLOAD_CONTAINER)
        self.harness.charm.setup_fga_auth_model(container)

        # Ensure POST was called and the state updated to the new id
        self.assertTrue(mock_post.called)
        self.assertEqual(self.harness.charm._state.openfga_auth_model_id, "new-id")

    @mock.patch("src.openfga_client.requests.post")
    @mock.patch("src.openfga_client.requests.get")
    def test_setup_fga_auth_model_recreated_when_missing(self, mock_get, mock_post):
        # Prepare the local model file with minimal content
        self.harness.enable_hooks()
        local_model = {"schema_version": "1.1", "type_definitions": []}
        self._write_openfga_model(local_model)

        # Existing model id in state to trigger comparison path
        self.harness.charm._state.openfga_auth_model_id = "existing-id"

        # Mock GET to return a missing "error" message to force a create
        def mocked_requests_get(*args, **kwargs):
            class MockResponse:
                def __init__(self, json_data, status_code):
                    self.json_data = json_data
                    self.status_code = status_code
                    self.ok = False

                def json(self):
                    return self.json_data

            # The specific error code should trigger a model creation
            return MockResponse(
                {"code": "authorization_model_not_found", "message": "Authorization Model 'fake-model' not found"}, 400
            )

        mock_get.side_effect = mocked_requests_get

        # Mock POST to return a new model id
        def mocked_requests_post(*args, **kwargs):
            class MockResponse:
                def __init__(self, json_data, status_code):
                    self.json_data = json_data
                    self.status_code = status_code
                    self.ok = True

                def json(self):
                    return self.json_data

            return MockResponse({"authorization_model_id": "new-id"}, 200)

        mock_post.side_effect = mocked_requests_post

        self.add_openfga_relation()
        container = self.harness.model.unit.get_container(WORKLOAD_CONTAINER)
        self.harness.charm.setup_fga_auth_model(container)

        # Ensure POST was called and the state updated to the new id
        self.assertTrue(mock_post.called)
        self.assertEqual(self.harness.charm._state.openfga_auth_model_id, "new-id")

    def test_session_secret_length(self):
        secret_dict = new_session_key()
        self.assertTrue(len(secret_dict[SESSION_KEY_LOOKUP]) >= 64)

    def test_new_jwks_secret_returns_consistent_key_material(self):
        activate_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expires_at = activate_at + timedelta(days=1)

        secret_dict = new_jwks_secret(activate_at, expires_at)

        self.assertEqual(
            set(secret_dict),
            {
                JWKS_ACTIVATE_AT_LOOKUP,
                JWKS_EXPIRES_AT_LOOKUP,
                JWKS_KID_LOOKUP,
                JWKS_PRIVATE_KEY_LOOKUP,
                JWKS_PUBLIC_JWK_LOOKUP,
            },
        )
        self.assertEqual(secret_dict[JWKS_ACTIVATE_AT_LOOKUP], activate_at.isoformat())
        self.assertEqual(secret_dict[JWKS_EXPIRES_AT_LOOKUP], expires_at.isoformat())
        self.assertTrue(is_valid_private_key(secret_dict[JWKS_PRIVATE_KEY_LOOKUP]))

        public_jwk = json.loads(secret_dict[JWKS_PUBLIC_JWK_LOOKUP])
        self.assertEqual(public_jwk["alg"], "RS256")
        self.assertEqual(public_jwk["kid"], secret_dict[JWKS_KID_LOOKUP])
        self.assertEqual(public_jwk["use"], "sig")

        derived_public_jwk = (
            CryptographyRSAKey(secret_dict[JWKS_PRIVATE_KEY_LOOKUP].encode(), Algorithms.RS256).public_key().to_dict()
        )
        self.assertDictEqual(
            public_jwk,
            derived_public_jwk
            | {
                "alg": "RS256",
                "kid": secret_dict[JWKS_KID_LOOKUP],
                "use": "sig",
            },
        )

    def test_rotate_session_key_action(self):
        # Stop the fake session secret patcher to test the secret rotation.
        self.start_minimal_jimm()
        self.fake_session_secret_patcher.stop()

        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)
        # Check the that the plan was updated
        plan = self.harness.get_container_pebble_plan("jimm")
        old_session_secret = plan.services[JIMM_SERVICE_NAME].environment["JIMM_SESSION_SECRET_KEY"]
        self.harness.run_action("rotate-session-key")
        new_plan = self.harness.get_container_pebble_plan("jimm")
        new_session_secret = new_plan.services[JIMM_SERVICE_NAME].environment["JIMM_SESSION_SECRET_KEY"]
        self.assertTrue(len(old_session_secret) > 0)
        self.assertTrue(len(new_session_secret) > 0)
        self.assertNotEqual(old_session_secret, new_session_secret)

    def test_jwks_rotation_lifecycle(self):
        """
        Test the full lifecycle of JWKS rotation. We intentionally go through 2 rotation
        cycles (i.e. 3 keys) to confirm that the charm correctly re-uses secrets.
        """
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        # Seed the first secret and verify the workload starts by publishing only the initial key.
        with mock.patch.object(JimmOperatorCharm, "_now", return_value=base_time):
            self.start_minimal_jimm(
                jwks_materials=[
                    (TEST_JWKS_PUBLIC_1, TEST_JWKS_PRIVATE_KEY_1),
                    (TEST_JWKS_PUBLIC_2, TEST_JWKS_PRIVATE_KEY_2),
                    (TEST_JWKS_PUBLIC_3, TEST_JWKS_PRIVATE_KEY_3),
                ]
            )

        initial_env = self.harness.get_container_pebble_plan("jimm").services[JIMM_SERVICE_NAME].environment
        self.assertEqual(initial_env["JIMM_JWKS_PATH"], str(JWKS_PATH))
        self.assertEqual(initial_env["JIMM_JWKS_PRIVATE_KEY_PATH"], str(JWKS_PRIVATE_KEY_PATH))
        self.assertEqual(json.loads(self.read_workload_file(JWKS_PATH)), {"keys": [TEST_JWKS_PUBLIC_1]})
        self.assertEqual(self.read_workload_file(JWKS_PRIVATE_KEY_PATH), TEST_JWKS_PRIVATE_KEY_1)

        # Enter the pre-rotation window and confirm the next public key is published early.
        publish_time = base_time + JWKS_ROTATION_PERIOD - JWKS_PRE_ROTATION_INTERVAL
        with mock.patch.object(JimmOperatorCharm, "_now", return_value=publish_time):
            self.harness.charm.on.update_status.emit()

        self.assertEqual(
            json.loads(self.read_workload_file(JWKS_PATH)), {"keys": [TEST_JWKS_PUBLIC_1, TEST_JWKS_PUBLIC_2]}
        )
        self.assertEqual(self.read_workload_file(JWKS_PRIVATE_KEY_PATH), TEST_JWKS_PRIVATE_KEY_1)

        # Once the propagation delay has elapsed, signing should switch to the new private key.
        switch_time = publish_time + JWKS_PROPAGATION_DELAY
        with mock.patch.object(JimmOperatorCharm, "_now", return_value=switch_time):
            self.harness.charm.on.update_status.emit()

        self.assertEqual(
            json.loads(self.read_workload_file(JWKS_PATH)), {"keys": [TEST_JWKS_PUBLIC_1, TEST_JWKS_PUBLIC_2]}
        )
        self.assertEqual(self.read_workload_file(JWKS_PRIVATE_KEY_PATH), TEST_JWKS_PRIVATE_KEY_2)

        # After the old key expires it should disappear from the JWKS, while the secret remains reusable.
        cleanup_time = base_time + JWKS_ROTATION_PERIOD + timedelta(minutes=1)
        with mock.patch.object(JimmOperatorCharm, "_now", return_value=cleanup_time):
            self.harness.charm.on.update_status.emit()

        self.assertEqual(json.loads(self.read_workload_file(JWKS_PATH)), {"keys": [TEST_JWKS_PUBLIC_2]})
        self.assertEqual(self.read_workload_file(JWKS_PRIVATE_KEY_PATH), TEST_JWKS_PRIVATE_KEY_2)

        # Enter the next rotation window and confirm the third key is published before activation.
        second_publish_time = switch_time + JWKS_ROTATION_PERIOD - JWKS_PRE_ROTATION_INTERVAL
        with mock.patch.object(JimmOperatorCharm, "_now", return_value=second_publish_time):
            self.harness.charm.on.update_status.emit()

        self.assertEqual(
            json.loads(self.read_workload_file(JWKS_PATH)), {"keys": [TEST_JWKS_PUBLIC_2, TEST_JWKS_PUBLIC_3]}
        )
        self.assertEqual(self.read_workload_file(JWKS_PRIVATE_KEY_PATH), TEST_JWKS_PRIVATE_KEY_2)

        # After the second propagation delay elapses, signing should switch to the third key.
        second_switch_time = second_publish_time + JWKS_PROPAGATION_DELAY
        with mock.patch.object(JimmOperatorCharm, "_now", return_value=second_switch_time):
            self.harness.charm.on.update_status.emit()

        self.assertEqual(
            json.loads(self.read_workload_file(JWKS_PATH)), {"keys": [TEST_JWKS_PUBLIC_2, TEST_JWKS_PUBLIC_3]}
        )
        self.assertEqual(self.read_workload_file(JWKS_PRIVATE_KEY_PATH), TEST_JWKS_PRIVATE_KEY_3)

        # Once the second key expires, only the third key should remain published.
        second_cleanup_time = switch_time + JWKS_ROTATION_PERIOD + timedelta(minutes=1)
        with mock.patch.object(JimmOperatorCharm, "_now", return_value=second_cleanup_time):
            self.harness.charm.on.update_status.emit()

        self.assertEqual(json.loads(self.read_workload_file(JWKS_PATH)), {"keys": [TEST_JWKS_PUBLIC_3]})
        self.assertEqual(self.read_workload_file(JWKS_PRIVATE_KEY_PATH), TEST_JWKS_PRIVATE_KEY_3)

    def test_jwks_rotation_does_not_create_multiple_future_keys(self):
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        # Seed the initial key and verify we only have one secret before pre-rotation begins.
        with mock.patch.object(JimmOperatorCharm, "_now", return_value=base_time):
            self.start_minimal_jimm(
                jwks_materials=[
                    (TEST_JWKS_PUBLIC_1, TEST_JWKS_PRIVATE_KEY_1),
                    (TEST_JWKS_PUBLIC_2, TEST_JWKS_PRIVATE_KEY_2),
                ]
            )

        self.assertEqual(len(self.existing_jwks_secrets()), 1)

        # The first update_status in the pre-rotation window should create exactly one future key.
        publish_time = base_time + JWKS_ROTATION_PERIOD - JWKS_PRE_ROTATION_INTERVAL
        with mock.patch.object(JimmOperatorCharm, "_now", return_value=publish_time):
            self.harness.charm.on.update_status.emit()

        published_secret_ids = {
            label: self.secret_identity(secret) for label, secret in self.existing_jwks_secrets().items()
        }
        self.assertEqual(len(published_secret_ids), 2)

        # Re-running before activation must not allocate a third secret or rewrite the two.
        before_activation_time = publish_time + JWKS_PROPAGATION_DELAY - timedelta(minutes=1)
        with mock.patch.object(JimmOperatorCharm, "_now", return_value=before_activation_time):
            self.harness.charm.on.update_status.emit()

        self.assertEqual(
            {label: self.secret_identity(secret) for label, secret in self.existing_jwks_secrets().items()},
            published_secret_ids,
        )
        self.assertEqual(
            json.loads(self.read_workload_file(JWKS_PATH)), {"keys": [TEST_JWKS_PUBLIC_1, TEST_JWKS_PUBLIC_2]}
        )
        self.assertEqual(self.read_workload_file(JWKS_PRIVATE_KEY_PATH), TEST_JWKS_PRIVATE_KEY_1)

    def test_default_host_key_is_valid(self):
        self.start_minimal_jimm()

        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)
        old_plan = self.harness.get_container_pebble_plan("jimm")
        old_session_secret = old_plan.services[JIMM_SERVICE_NAME].environment["JIMM_SSH_HOST_KEY"]
        # assert the default
        self.assertTrue(is_valid_private_key(old_session_secret))

    def test_set_host_key_config(self):
        self.start_minimal_jimm()

        # Set the config as a new secret
        host_key = new_host_key()[HOST_KEY_LOOKUP]
        secret_id = self.harness.add_user_secret({"hostkey": host_key})
        self.harness.grant_secret(secret_id, "juju-jimm-k8s")
        self.harness.update_config(MINIMAL_CONFIG)
        self.harness.update_config({"ssh-host-key-secret-id": secret_id})
        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        new_plan = self.harness.get_container_pebble_plan("jimm")
        new_session_secret = new_plan.services[JIMM_SERVICE_NAME].environment["JIMM_SSH_HOST_KEY"]
        self.assertEqual(new_session_secret, host_key)

        self.assertEqual(self.harness.charm.unit.status.name, ActiveStatus.name)

    def test_set_host_key_config_invalid_key(self):
        self.start_minimal_jimm()

        # Set the config as a new secret
        secret_id = self.harness.add_user_secret({"hostkey": "invalid-key"})
        self.harness.grant_secret(secret_id, "juju-jimm-k8s")
        self.harness.update_config(MINIMAL_CONFIG)
        self.harness.update_config({"ssh-host-key-secret-id": secret_id})

        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)
        # expect the charm to be blocked
        self.assertEqual(self.harness.charm.unit.status.name, BlockedStatus.name)
        self.assertEqual(self.harness.charm.unit.status.message, "hostkey retrieval failed. Check juju debug logs.")

    def test_change_host_key_secret_content(self):
        self.start_minimal_jimm()

        # Set the config as a new secret
        host_key = new_host_key()[HOST_KEY_LOOKUP]
        secret_id = self.harness.add_user_secret({"hostkey": "invalid"})
        self.harness.grant_secret(secret_id, "juju-jimm-k8s")
        self.harness.update_config(MINIMAL_CONFIG)
        self.harness.update_config({"ssh-host-key-secret-id": secret_id})
        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)
        self.assertEqual(self.harness.charm.unit.status.name, BlockedStatus.name)

        # Update the secret content
        self.harness.set_secret_content(secret_id, {"hostkey": host_key})
        self.harness.charm.on.jimm_pebble_ready.emit(container)
        new_plan = self.harness.get_container_pebble_plan("jimm")
        new_session_secret = new_plan.services[JIMM_SERVICE_NAME].environment["JIMM_SSH_HOST_KEY"]
        self.assertEqual(new_session_secret, host_key)
        self.assertEqual(self.harness.charm.unit.status.name, ActiveStatus.name)

    @mock.patch.object(ops.model.Unit, "is_leader")
    def test_rotate_session_key_action_non_leader(self, is_leader):
        self.start_minimal_jimm()

        # Set is_leader to return false to mimic a non-leader unit.
        is_leader.return_value = False
        with self.assertRaises(ActionFailed) as e:
            self.harness.run_action("rotate-session-key")
        self.assertEqual(e.exception.message, "Run this action on the leader unit")

    @mock.patch.object(ops.model.Unit, "is_leader")
    def test_plan_on_non_leader(self, is_leader):
        is_leader.return_value = True
        self.start_minimal_jimm()

        container = self.harness.model.unit.get_container("jimm")
        # Set is_leader to return false to mimic a non-leader unit.
        is_leader.return_value = False
        self.harness.charm.on.jimm_pebble_ready.emit(container)
        plan = self.harness.get_container_pebble_plan("jimm")
        expected_plan = copy.deepcopy(get_expected_plan(EXPECTED_VAULT_ENV))
        del expected_plan["services"][JIMM_SERVICE_NAME]["environment"]["JIMM_IS_LEADER"]
        self.assertEqual(plan.to_dict(), expected_plan)

    def test_egress_subnet_via_binding(self):
        binding = self.harness.charm.model.get_binding("peer")
        subnets = self.harness.charm._egress_subnets(binding)
        # Perform a regex match that the result is an IP address
        self.assertGreaterEqual(len(subnets), 1)
        for subnet in subnets:
            self.assertRegex(subnet, r"^([0-9]{1,3}\.){3}[0-9]{1,3}($|/(\d{2}))$")

    def test_cors_allowed_origins(self):
        self.start_minimal_jimm()

        self.harness.update_config({"cors-allowed-origins": "http://test.localhost"})
        plan = self.harness.get_container_pebble_plan("jimm")
        expected_env = EXPECTED_VAULT_ENV.copy()
        expected_env.update({"CORS_ALLOWED_ORIGINS": "http://test.localhost"})
        self.assertEqual(plan.to_dict(), get_expected_plan(expected_env))

    def test_remove_oauth_relation(self):
        self.start_minimal_jimm()
        self.assertEqual(
            self.harness.charm.unit.get_container(WORKLOAD_CONTAINER).get_service(JIMM_SERVICE_NAME).is_running(), True
        )

        self.harness.remove_relation(self.oauth_rel_id)

        self.assertEqual(
            self.harness.charm.unit.get_container(WORKLOAD_CONTAINER).get_service(JIMM_SERVICE_NAME).is_running(), False
        )
        self.assertEqual(self.harness.charm.unit.status.message, "Waiting for OAuth relation")
        self.assertEqual(self.harness.charm.unit.status.name, "blocked")

    def test_update_trusted_ca_certs(self):
        self.start_minimal_jimm()

        self.harness.handle_exec(
            WORKLOAD_CONTAINER,
            ["update-ca-certificates"],
            result=0,
        )
        self.add_certificate_transfer_relation()

        plan = self.harness.get_container_pebble_plan("jimm")
        self.assertEqual(plan.to_dict(), get_expected_plan(EXPECTED_VAULT_ENV))

        # Assert the CA bundle file contains the dummy certs
        root = self.harness.get_filesystem_root(WORKLOAD_CONTAINER)
        ca_bundle_path = pathlib.Path(root) / TRUSTED_CA_PATH.relative_to("/")
        ca_bundle_content = ca_bundle_path.read_text()
        self.assertIn("cert1", ca_bundle_content)
        self.assertIn("cert2", ca_bundle_content)

        container = self.harness.model.unit.get_container("jimm")
        force_restart = self.harness.charm._update_trusted_ca_certs(container)
        self.assertFalse(force_restart)

    def test_receive_certs_as_non_leader(self):
        self.start_minimal_jimm()
        self.harness.set_leader(False)
        self.harness.handle_exec(
            WORKLOAD_CONTAINER,
            ["update-ca-certificates"],
            result=0,
        )
        self.add_certificate_transfer_relation()

        plan = self.harness.get_container_pebble_plan("jimm")
        expected_env = EXPECTED_VAULT_ENV.copy()
        del expected_env["JIMM_IS_LEADER"]
        self.assertEqual(plan.to_dict(), get_expected_plan(expected_env))

        # Assert the CA bundle file contains the dummy certs
        root = self.harness.get_filesystem_root(WORKLOAD_CONTAINER)
        ca_bundle_path = pathlib.Path(root) / TRUSTED_CA_PATH.relative_to("/")
        ca_bundle_content = ca_bundle_path.read_text()
        self.assertIn("cert1", ca_bundle_content)
        self.assertIn("cert2", ca_bundle_content)

    def add_tracing_relation(self, endpoint="http://tempo.localhost:2331"):
        """Add a tracing relation with a simulated tempo endpoint."""
        self.tracing_rel_id = self.harness.add_relation("tracing", "tempo-coordinator-k8s")
        self.harness.add_relation_unit(self.tracing_rel_id, "tempo-coordinator-k8s/0")
        self.harness.update_relation_data(
            self.tracing_rel_id,
            "tempo-coordinator-k8s",
            {
                "receivers": json.dumps(
                    [
                        {
                            "protocol": {"name": "otlp_http", "type": "http"},
                            "url": endpoint,
                        }
                    ]
                )
            },
        )

    def test_tracing_relation_adds_otel_env_vars(self):
        self.start_minimal_jimm()

        self.add_tracing_relation()

        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        plan = self.harness.get_container_pebble_plan("jimm")
        env = plan.to_dict().get("services", {}).get(JIMM_SERVICE_NAME, {}).get("environment", {})
        self.assertEqual(env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"), "http://tempo.localhost:2331")
        self.assertEqual(env.get("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"), "http/protobuf")
        self.assertEqual(env.get("OTEL_SERVICE_NAME"), "juju-jimm-k8s")
        self.assertEqual(env.get("OTEL_TRACES_SAMPLE_RATIO"), "0.1")

    def test_tracing_relation_does_not_add_otel_env_vars_when_not_ready(self):
        self.start_minimal_jimm()

        # Add tracing relation but without provider data
        self.tracing_rel_id = self.harness.add_relation("tracing", "tempo-coordinator-k8s")
        self.harness.add_relation_unit(self.tracing_rel_id, "tempo-coordinator-k8s/0")

        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        plan = self.harness.get_container_pebble_plan("jimm")
        env = plan.to_dict().get("services", {}).get(JIMM_SERVICE_NAME, {}).get("environment", {})
        self.assertNotIn("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", env)
        self.assertNotIn("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", env)
        self.assertNotIn("OTEL_SERVICE_NAME", env)
        self.assertNotIn("OTEL_TRACES_SAMPLE_RATIO", env)


def _format_test_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
