# Copyright 2022 Canonical Ltd
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing


import copy
import json
import os
import pathlib
import tempfile
from unittest import TestCase, mock

import ops
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.testing import ActionFailed, Harness

from src.charm import (
    JIMM_SERVICE_NAME,
    SESSION_KEY_LOOKUP,
    WORKLOAD_CONTAINER,
    JimmOperatorCharm,
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

BASE_ENV = {
    "JIMM_DASHBOARD_LOCATION": "https://jaas.ai/models",
    "JIMM_DNS_NAME": "jimm.localhost",
    "JIMM_LISTEN_ADDR": ":8080",
    "JIMM_LOG_LEVEL": "info",
    "JIMM_UUID": "1234567890",
    "JIMM_IS_LEADER": "True",
    "BAKERY_PRIVATE_KEY": "ly/dzsI9Nt/4JxUILQeAX79qZ4mygDiuYGqc2ZEiDEc=",
    "BAKERY_PUBLIC_KEY": "izcYsQy3TePp6bLjqOo3IRPFvkQd2IKtyODGqC6SdFk=",
    "OPENFGA_AUTH_MODEL": 1,
    "JIMM_AUDIT_LOG_RETENTION_PERIOD_IN_DAYS": "0",
    "JIMM_MACAROON_EXPIRY_DURATION": "24h",
    "JIMM_JWT_EXPIRY": "5m",
    "JIMM_ACCESS_TOKEN_EXPIRY_DURATION": "6h",
    "JIMM_OAUTH_ISSUER_URL": OAUTH_PROVIDER_INFO["issuer_url"],
    "JIMM_OAUTH_CLIENT_ID": OAUTH_CLIENT_ID,
    "JIMM_OAUTH_CLIENT_SECRET": OAUTH_CLIENT_SECRET,
    "JIMM_OAUTH_SCOPES": OAUTH_PROVIDER_INFO["scope"],
    "JIMM_DASHBOARD_FINAL_REDIRECT_URL": "https://jaas.ai/models",
    "JIMM_SECURE_SESSION_COOKIES": True,
    "JIMM_SESSION_COOKIE_MAX_AGE": 86400,
    "JIMM_SESSION_SECRET_KEY": "test-secret",
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


class MockExec:
    def wait_output():
        return True


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

    def use_fake_session_secret(self):
        patcher = mock.patch("src.charm.new_session_key", return_value={SESSION_KEY_LOOKUP: "test-secret"})
        self.mock_key = patcher.start()
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
        root = self.harness.get_filesystem_root(WORKLOAD_CONTAINER)
        dir_path = root / "root" / "openfga"
        dir_path.mkdir(parents=True)
        (dir_path / "authorisation_model.json").write_text("null")
        self.harness.charm._state.openfga_auth_model_hash = "37a6259cc0c1dae299a7866489dff0bd"
        self.harness.charm._state.openfga_auth_model_id = 1

    def ensure_jimm_secrets(self):
        self.harness.enable_hooks()
        self.harness.charm.on.install.emit()

    def start_minimal_jimm(self):
        self.harness.enable_hooks()
        self.harness.charm._state.dsn = "postgres-dsn"
        self.create_auth_model_info()
        self.add_openfga_relation()
        self.add_vault_relation()
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
        self.use_fake_session_secret()
        self.harness.enable_hooks()
        self.create_auth_model_info()
        self.add_vault_relation()
        self.harness.update_config(MINIMAL_CONFIG)

        container = self.harness.model.unit.get_container("jimm")
        # Emit the pebble-ready event for jimm
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        # Check the that the plan was updated
        plan = self.harness.get_container_pebble_plan("jimm")
        self.assertEqual(plan.to_dict(), get_expected_plan(EXPECTED_VAULT_ENV))

    def test_ready_without_plan(self):
        self.harness.enable_hooks()
        self.harness.charm._ready()
        self.assertEqual(self.harness.charm.unit.status.name, BlockedStatus.name)
        self.assertEqual(self.harness.charm.unit.status.message, "Waiting for OAuth relation")

    def test_on_config_changed(self):
        self.use_fake_session_secret()
        self.harness.enable_hooks()
        self.create_auth_model_info()
        self.add_vault_relation()
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
            self.harness.charm._state.dsn, "postgresql://postgres-user:postgres-pass@local-1.localhost/jimm"
        )

    def test_postgres_secret_storage_config(self):
        self.use_fake_session_secret()
        self.ensure_jimm_secrets()
        self.create_auth_model_info()
        self.harness.update_config(MINIMAL_CONFIG)
        self.harness.update_config({"postgres-secret-storage": True})
        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        plan = self.harness.get_container_pebble_plan("jimm")
        expected_env = BASE_ENV.copy()
        expected_env.update({"INSECURE_SECRET_STORAGE": "enabled"})
        self.assertEqual(plan.to_dict(), get_expected_plan(expected_env))

    def test_proxy_settings(
        self,
    ):
        os.environ["JUJU_CHARM_NO_PROXY"] = "no-proxy.canonincal.com"
        os.environ["JUJU_CHARM_HTTP_PROXY"] = "http-proxy.canonincal.com"
        os.environ["JUJU_CHARM_HTTPS_PROXY"] = "https-proxy.canonincal.com"
        self.use_fake_session_secret()
        self.ensure_jimm_secrets()
        self.create_auth_model_info()
        self.harness.update_config(MINIMAL_CONFIG)
        self.harness.update_config({"postgres-secret-storage": True})
        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        plan = self.harness.get_container_pebble_plan("jimm")
        expected_env = BASE_ENV.copy()
        expected_env.update({"INSECURE_SECRET_STORAGE": "enabled"})
        expected_env.update({"NO_PROXY": "no-proxy.canonincal.com"})
        expected_env.update({"HTTP_PROXY": "http-proxy.canonincal.com"})
        expected_env.update({"HTTPS_PROXY": "https-proxy.canonincal.com"})
        self.assertEqual(plan.to_dict(), get_expected_plan(expected_env))

        os.environ["JUJU_CHARM_NO_PROXY"] = ""
        os.environ["JUJU_CHARM_HTTP_PROXY"] = ""
        os.environ["JUJU_CHARM_HTTPS_PROXY"] = ""

    def test_dashboard_config(self):
        self.create_auth_model_info()
        self.harness.enable_hooks()
        self.add_vault_relation()
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
        self.assertDictEqual(
            plan.to_dict()["services"]["jimm"]["environment"],
            plan.to_dict()["services"]["jimm"]["environment"] | expected_values,
        )

    def test_app_dns_address(self):
        self.harness.update_config(MINIMAL_CONFIG)
        self.harness.update_config({"dns-name": "jimm.com"})
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

    def test_audit_log_retention_config(self):
        self.use_fake_session_secret()
        self.harness.enable_hooks()
        self.create_auth_model_info()
        self.add_vault_relation()
        container = self.harness.model.unit.get_container("jimm")
        self.harness.charm.on.jimm_pebble_ready.emit(container)

        self.harness.update_config(MINIMAL_CONFIG)
        self.harness.update_config({"audit-log-retention-period-in-days": "10"})

        # Emit the pebble-ready event for jimm
        self.harness.charm.on.jimm_pebble_ready.emit(container)
        expected_env = EXPECTED_VAULT_ENV.copy()
        expected_env.update({"JIMM_AUDIT_LOG_RETENTION_PERIOD_IN_DAYS": "10"})
        # Check the that the plan was updated
        plan = self.harness.get_container_pebble_plan("jimm")
        self.assertEqual(plan.to_dict(), get_expected_plan(expected_env))

    def test_dashboard_relation_joined(self):
        harness = Harness(JimmOperatorCharm)
        self.addCleanup(harness.cleanup)

        id = harness.add_relation("peer", "juju-jimm-k8s")
        harness.add_relation_unit(id, "juju-jimm-k8s/1")
        harness.begin()
        harness.set_leader(True)
        harness.update_config(
            {
                "dns-name": "jimm.localhost",
                "controller-admins": "user1 user2 group1",
                "uuid": "caaa4ba4-e2b5-40dd-9bf3-2bd26d6e17aa",
            }
        )

        id = harness.add_relation("dashboard", "juju-dashboard")
        harness.add_relation_unit(id, "juju-dashboard/0")
        data = harness.get_relation_data(id, "juju-jimm-k8s")

        self.assertTrue(data)
        self.assertEqual(
            data["controller_url"],
            "wss://jimm.localhost",
        )
        self.assertEqual(data["is_juju"], "False")

    def test_vault_relation_joined(self):
        self.use_fake_session_secret()
        self.create_auth_model_info()
        self.harness.enable_hooks()
        self.add_vault_relation()

        self.harness.update_config(MINIMAL_CONFIG)
        plan = self.harness.get_container_pebble_plan("jimm")
        self.assertEqual(plan.to_dict(), get_expected_plan(EXPECTED_VAULT_ENV))

    def test_app_blocked_without_private_key(self):
        self.harness.enable_hooks()
        # Fake the Postgres relation.
        self.harness.charm._state.dsn = "postgres-dsn"
        # Setup the OpenFGA relation.
        self.create_auth_model_info()
        self.add_openfga_relation()
        self.add_vault_relation()
        self.harness.charm._state.openfga_auth_model_id = 1
        # Set the config with the private-key value missing.
        min_config_no_private_key = MINIMAL_CONFIG.copy()
        del min_config_no_private_key["private-key"]
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

    @mock.patch("src.charm.requests.post")
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
        root = self.harness.get_filesystem_root(WORKLOAD_CONTAINER)
        dir_path = root / "root" / "openfga"
        dir_path.mkdir(parents=True)
        (dir_path / "authorisation_model.json").write_text("null")
        self.add_openfga_relation()
        self.assertEqual(self.harness.charm._state.openfga_auth_model_id, 123)
        self.assertNotEqual(self.harness.charm._state.openfga_auth_model_hash, "")

    def test_setup_fga_auth_model_skipped_when_auth_model_exists(self):
        self.harness.enable_hooks()
        root = self.harness.get_filesystem_root(WORKLOAD_CONTAINER)
        dir_path = root / "root" / "openfga"
        dir_path.mkdir(parents=True)
        (dir_path / "authorisation_model.json").write_text("null")
        self.harness.charm._state.openfga_auth_model_hash = "37a6259cc0c1dae299a7866489dff0bd"
        with self.assertLogs() as cm:
            self.add_openfga_relation()
            found = False
            for line in cm.output:
                found |= "auth model already exists, won't recreate" in line
            self.assertTrue(found)
        self.assertEqual(self.harness.charm._state.openfga_auth_model_id, None)

    def test_session_secret_length(self):
        secret_dict = new_session_key()
        self.assertTrue(len(secret_dict[SESSION_KEY_LOOKUP]) >= 64)

    def test_rotate_session_key_action(self):
        self.harness.enable_hooks()
        self.create_auth_model_info()
        self.add_vault_relation()
        self.harness.update_config(MINIMAL_CONFIG)

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

    @mock.patch.object(ops.model.Unit, "is_leader")
    def test_rotate_session_key_action_non_leader(self, is_leader):
        is_leader.return_value = False
        self.harness.enable_hooks()
        self.create_auth_model_info()
        self.add_vault_relation()
        self.harness.update_config(MINIMAL_CONFIG)
        with self.assertRaises(ActionFailed) as e:
            self.harness.run_action("rotate-session-key")
        self.assertEqual(e.exception.message, "Run this action on the leader unit")

    @mock.patch.object(ops.model.Unit, "is_leader")
    def test_plan_on_non_leader(self, is_leader):
        self.use_fake_session_secret()
        # Ensure we are leader in order to create the secret.
        is_leader.return_value = True
        self.harness.enable_hooks()
        self.create_auth_model_info()
        self.add_vault_relation()
        self.harness.update_config(MINIMAL_CONFIG)
        container = self.harness.model.unit.get_container("jimm")
        # Set is_leader to return false to mimic a non-leader unit.
        is_leader.return_value = False
        self.harness.charm.on.jimm_pebble_ready.emit(container)
        plan = self.harness.get_container_pebble_plan("jimm")
        expected_plan = copy.deepcopy(get_expected_plan(EXPECTED_VAULT_ENV))
        del expected_plan["services"][JIMM_SERVICE_NAME]["environment"]["JIMM_IS_LEADER"]
        self.assertEqual(plan.to_dict(), expected_plan)

    def test_egress_subnet_via_config(self):
        self.harness.update_config({"egress-subnet": "10.0.0.0/8"})
        res = self.harness.charm._egress_subnet(None)
        self.assertEqual(res, "10.0.0.0/8")

    def test_egress_subnet_via_binding(self):
        binding = self.harness.charm.model.get_binding("peer")
        res = self.harness.charm._egress_subnet(binding)
        # Perform a regex match that the result is an IP address
        self.assertRegexpMatches(res, r"^([0-9]{1,3}\.){3}[0-9]{1,3}($|/(16|24))$")
