#!/usr/bin/env python3
# This file is part of the JIMM k8s Charm for Juju.
# Copyright 2024 Canonical Ltd.

import hashlib
import json
import logging
import os
import secrets
from base64 import b64encode, urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse
from uuid import uuid4

from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificatesAvailableEvent,
    CertificatesRemovedEvent,
    CertificateTransferRequires,
)
from charms.data_platform_libs.v0.data_interfaces import (
    DatabaseRequires,
    DatabaseRequiresEvent,
)
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.hydra.v0.oauth import ClientConfig, OAuthInfoChangedEvent, OAuthRequirer
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.nginx_ingress_integrator.v0.nginx_route import require_nginx_route
from charms.openfga_k8s.v1.openfga import OpenFGARequires, OpenFGAStoreCreateEvent
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateRevokedEvent,
    TLSCertificatesRequiresV1,
    generate_csr,
    generate_private_key,
)
from charms.traefik_k8s.v1.ingress_per_unit import (
    IngressPerUnitReadyForUnitEvent,
    IngressPerUnitRequirer,
)
from charms.traefik_k8s.v2.ingress import (
    IngressPerAppReadyEvent,
    IngressPerAppRequirer,
    IngressPerAppRevokedEvent,
)
from charms.vault_k8s.v0 import vault_kv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from ops import pebble
from ops.charm import (
    ActionEvent,
    CharmBase,
    InstallEvent,
    RelationDepartedEvent,
    RelationJoinedEvent,
    SecretChangedEvent,
    UpgradeCharmEvent,
)
from ops.main import main
from ops.model import (
    ActiveStatus,
    Binding,
    BlockedStatus,
    Container,
    Secret,
    SecretNotFoundError,
    TooManyRelatedAppsError,
    WaitingStatus,
)

from openfga_client import OpenFGAClient
from state import State, requires_state, requires_state_setter

logger = logging.getLogger(__name__)

WORKLOAD_CONTAINER = "jimm"

REQUIRED_SETTINGS = {
    "JIMM_UUID": "missing uuid configuration",
    "JIMM_DSN": "missing postgresql relation",
    "OPENFGA_STORE": "missing openfga relation",
    "OPENFGA_AUTH_MODEL": "waiting for OpenFGA auth model creation",
    "OPENFGA_HOST": "missing openfga relation",
    "OPENFGA_SCHEME": "missing openfga relation",
    "OPENFGA_TOKEN": "missing openfga relation",
    "OPENFGA_PORT": "missing openfga relation",
    "BAKERY_PRIVATE_KEY": "missing private key configuration",
    "BAKERY_PUBLIC_KEY": "missing public key configuration",
}

JIMM_SERVICE_NAME = "jimm"
DATABASE_NAME = "jimm"
OPENFGA_STORE_NAME = "jimm"
LOG_FILE = "/var/log/jimm"
# This likely will just be JIMM's port.
PROMETHEUS_PORT = 8080
OAUTH = "oauth"
OAUTH_SCOPES = "openid profile email offline_access"
# TODO: Add "device_code" below once the charm interface supports it.
OAUTH_GRANT_TYPES = ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"]
VAULT_NONCE_SECRET_LABEL = "nonce"
# Template for storing trusted certificate in a file.
TRUSTED_CA_PATH = Path("/usr/local/share/ca-certificates/trusted-ca-certs.crt")
SESSION_KEY_SECRET_LABEL = "session_key"
HOST_KEY_SECRET_LABEL = "host_key"
# Keys should be lowercase letters and digits, at least 3 characters long,
# start with a letter, and not start or end with a hyphen.
SESSION_KEY_LOOKUP = "sessionkey"
HOST_KEY_LOOKUP = "hostkey"
# Prefix used for application secrets that each hold one JWKS signing key lifecycle.
JWKS_SECRET_LABEL_PREFIX = "jwks-key-"
# Secret content keys for the public/private key material and its stable key id.
JWKS_KID_LOOKUP = "kid"
JWKS_PUBLIC_JWK_LOOKUP = "publicjwk"
JWKS_PRIVATE_KEY_LOOKUP = "privatekey"
# Secret content keys that define when a key starts signing and expires.
JWKS_ACTIVATE_AT_LOOKUP = "activateat"
JWKS_EXPIRES_AT_LOOKUP = "expiresat"

# JWKS Rotation time diagram
# Initial Key     New Key      Activate Key    Expire Old Key
#     |              |              |               |
# ----o--------------o--------------o---------------o------> Time
#     ^              ^              ^               ^
#    T=0          T=day 83     T=day 83 + 1h     T=day 90

# How long one signing key remains valid.
JWKS_ROTATION_PERIOD = timedelta(days=90)
# How far ahead of expiry the next public key is published for controllers to fetch.
JWKS_PRE_ROTATION_INTERVAL = timedelta(days=7)
# Delay between publishing a new public key and using its private key for signing.
JWKS_PROPAGATION_DELAY = timedelta(hours=1)
# Max-Age advertised with the JWKS endpoint so consumers know their cache lifetime.
JWKS_CACHE_MAX_AGE = 600
CERTIFICATE_TRANSFER_INTEGRATION_NAME = "receive-ca-cert"


class DeferError(Exception):
    """Used to indicate to the calling function that an event could be deferred
    if the hook needs to be retried."""

    pass


@dataclass(frozen=True)
class JWKSSecret:
    # Materialized view of one Juju secret holding a single JWKS signing key lifecycle.
    activate_at: datetime
    expires_at: datetime
    kid: str
    private_key: str
    public_jwk: dict[str, str]
    secret: Secret
    secret_id: str


class JimmOperatorCharm(CharmBase):
    """JIMM Operator Charm."""

    def __init__(self, *args):
        super().__init__(*args)

        self._state = State(self.app, lambda: self.model.get_relation("peer"))

        self.framework.observe(self.on.peer_relation_changed, self._on_peer_relation_changed)
        self.framework.observe(self.on.jimm_pebble_ready, self._on_jimm_pebble_ready)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.update_status, self._on_update_status)
        self.framework.observe(self.on.leader_elected, self._on_leader_elected)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.stop, self._on_stop)
        self.framework.observe(self.on.secret_changed, self.on_secret_changed)
        self.framework.observe(self.on.rotate_session_key_action, self.rotate_session_secret_key)

        self.framework.observe(
            self.on.dashboard_relation_joined,
            self._on_dashboard_relation_joined,
        )

        # Certificates relation
        self.certificates = TLSCertificatesRequiresV1(self, "certificates")
        self.framework.observe(
            self.on.certificates_relation_joined,
            self._on_certificates_relation_joined,
        )
        self.framework.observe(
            self.certificates.on.certificate_available,
            self._on_certificate_available,
        )
        self.framework.observe(
            self.certificates.on.certificate_expiring,
            self._on_certificate_expiring,
        )
        self.framework.observe(
            self.certificates.on.certificate_revoked,
            self._on_certificate_revoked,
        )

        # Traefik ingress relations
        self.ingress = IngressPerAppRequirer(
            self,
            relation_name="ingress",
            strip_prefix=True,
            port=8080,
        )
        self.internal_ingress = IngressPerAppRequirer(
            self,
            relation_name="internal-ingress",
            strip_prefix=True,
            port=9090,
        )

        # if the unit is the leader we set the port. We set the port just for the leader,
        # because IngressPerUnit is opening a port on the traefik charm, and it can't open the same
        # port multiple times. This should be solved once we have IngressPerApp in tcp mode.
        # https://github.com/canonical/traefik-k8s-operator/issues/440
        if self.unit.is_leader():
            self.ingress_ssh = IngressPerUnitRequirer(
                self, relation_name="ingress-ssh", mode="tcp", port=self._ssh_port
            )
        else:
            self.ingress_ssh = IngressPerUnitRequirer(self, relation_name="ingress-ssh", mode="tcp")

        self.framework.observe(self.ingress_ssh.on.ready_for_unit, self._on_ingress_ssh_ready)
        self.framework.observe(self.ingress_ssh.on.revoked_for_unit, self._on_ingress_ssh_revoked)

        self.framework.observe(self.ingress.on.ready, self._on_ingress_ready)
        self.framework.observe(
            self.ingress.on.revoked,
            self._on_ingress_revoked,
        )

        self.framework.observe(self.internal_ingress.on.ready, self._on_ingress_ready)
        self.framework.observe(
            self.internal_ingress.on.revoked,
            self._on_ingress_revoked,
        )

        # Nginx ingress relation
        require_nginx_route(
            charm=self,
            service_hostname=str(self.config.get("dns-name", "")),
            service_name=self.app.name,
            service_port=8080,
        )

        # OAuth relation
        # Set this up after ingress as the ingress object is used to construct redirect URLs.
        self.oauth = OAuthRequirer(self, self._oauth_client_config, relation_name=OAUTH)
        self.framework.observe(self.oauth.on.oauth_info_changed, self._on_oauth_info_changed)
        self.framework.observe(self.oauth.on.oauth_info_removed, self._on_oauth_info_changed)

        # Database relation
        self.database = DatabaseRequires(
            self,
            relation_name="database",
            database_name=DATABASE_NAME,
        )
        self.framework.observe(self.database.on.database_created, self._on_database_event)
        self.framework.observe(
            self.database.on.endpoints_changed,
            self._on_database_event,
        )
        self.framework.observe(
            self.on.database_relation_broken,
            self._on_database_relation_broken,
        )

        # OpenFGA relation
        self.openfga = OpenFGARequires(self, OPENFGA_STORE_NAME)
        self.framework.observe(
            self.openfga.on.openfga_store_created,
            self._on_openfga_store_created,
        )

        # Vault relation
        self.vault = vault_kv.VaultKvRequires(
            self,
            "vault",
            "jimm",
        )
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.upgrade_charm, self._on_upgrade)
        self.framework.observe(self.vault.on.connected, self._on_vault_connected)
        self.framework.observe(self.vault.on.ready, self._on_vault_ready)
        self.framework.observe(self.vault.on.gone_away, self._on_vault_gone_away)
        self.framework.observe(self.on.secret_changed, self._on_secret_changed)

        # Grafana relation
        self._grafana_dashboards = GrafanaDashboardProvider(self, relation_name="grafana-dashboard")

        # Loki relation
        self._log_forwarder = LogForwarder(self, relation_name="logging")

        # Prometheus relation
        self._prometheus_scraping = MetricsEndpointProvider(
            self,
            relation_name="metrics-endpoint",
            jobs=[{"static_configs": [{"targets": [f"*:{PROMETHEUS_PORT}"]}]}],
            refresh_event=self.on.config_changed,
        )

        self.trusted_cert_transfer = CertificateTransferRequires(self, CERTIFICATE_TRANSFER_INTEGRATION_NAME)
        self.framework.observe(
            self.trusted_cert_transfer.on.certificate_set_updated,
            self._on_trusted_certificate_available,
        )
        self.framework.observe(
            self.trusted_cert_transfer.on.certificates_removed,
            self._on_trusted_certificate_removed,
        )

    @property
    def _ssh_port(self) -> int:
        return int(self.config.get("ssh-port", 0))

    def _on_peer_relation_changed(self, event) -> None:
        self._update_workload(event)

    def _on_jimm_pebble_ready(self, event) -> None:
        self._update_workload(event)

    def _on_config_changed(self, event) -> None:
        self._update_workload(event)

    def _on_oauth_info_changed(self, event: OAuthInfoChangedEvent) -> None:
        self._update_workload(event)

    def _on_install(self, event: InstallEvent) -> None:
        self.unit.add_secret(
            {"nonce": secrets.token_hex(16)},
            label=VAULT_NONCE_SECRET_LABEL,
            description="Nonce for vault-kv relation",
        )
        self.ensure_session_secret_key()
        self.ensure_hostkey_secret_key()

    def _on_upgrade(self, event: UpgradeCharmEvent) -> None:
        self.ensure_session_secret_key()
        self.ensure_hostkey_secret_key()

    def _on_secret_changed(self, event: SecretChangedEvent) -> None:
        # Update the workload if ssh-host-key-secret-id is set in the config and the secret-changed event is fired.
        if self.config.get("ssh-host-key-secret-id") != "" and event.secret.id == self.config.get(
            "ssh-host-key-secret-id"
        ):
            self._update_workload(event)

    @requires_state_setter
    def _on_leader_elected(self, event) -> None:
        if not self._state.private_key:
            private_key: bytes = generate_private_key(key_size=4096)
            self._state.private_key = private_key.decode()

        self.ensure_jwks_secret_key()

        self._update_workload(event)

    def _vault_config(self) -> dict | None:
        try:
            relation = self.model.get_relation("vault")
        except TooManyRelatedAppsError:
            logger.error("too many vault relations detected")
            raise RuntimeError("More than one relations are defined. Please provide a relation_id")
        if relation is None:
            return None

        vault_url = self.vault.get_vault_url(relation)
        ca_certificate = self.vault.get_ca_certificate(relation)
        mount = self.vault.get_mount(relation)
        unit_credentials = self.vault.get_unit_credentials(relation)
        if not unit_credentials:
            logger.debug("no vault unit credentials")
            return None

        # unit_credentials is a juju secret id
        secret = self.model.get_secret(id=unit_credentials)
        secret_content = secret.get_content(refresh=True)
        role_id = secret_content["role-id"]
        role_secret_id = secret_content["role-secret-id"]

        return {
            "VAULT_ADDR": vault_url,
            "VAULT_CACERT_BYTES": ca_certificate,
            "VAULT_ROLE_ID": role_id,
            "VAULT_ROLE_SECRET_ID": role_secret_id,
            "VAULT_PATH": mount,
        }

    @requires_state
    def _update_workload(self, event) -> None:
        """Update workload with all available configuration
        data."""

        container = self.unit.get_container(WORKLOAD_CONTAINER)
        if not container.can_connect():
            logger.info("cannot connect to the workload container - deferring the event")
            event.defer()
            return

        # Wait for OAuth relations
        self.oauth.update_client_config(client_config=self._oauth_client_config)
        if not self.oauth.is_client_created():
            logger.warning("OAuth relation is not ready yet")
            self.unit.status = BlockedStatus("Waiting for OAuth relation")
            self._stop()
            return

        # Wait for database relation
        if not self.database.is_resource_created():
            logger.warning("database relation is not ready yet")
            self.unit.status = BlockedStatus("Waiting for database relation")
            return

        # Wait for OpenFGA relations
        openfga_info = self.openfga.get_store_info()
        if not openfga_info:
            logger.warning("OpenFGA relation is not ready yet")
            self.unit.status = BlockedStatus("Waiting for OpenFGA relation")
            return
        openfga_url_details = urlparse(openfga_info.http_api_url)

        self.setup_fga_auth_model(container)

        dns_name = self._get_dns_name(event)
        if not dns_name:
            logger.warning("dns name not set")
            return

        parsed_dns_name = urlparse(dns_name)
        if parsed_dns_name.scheme:
            dns_without_scheme = f"{parsed_dns_name.netloc}{parsed_dns_name.path}"
        else:
            dns_without_scheme = dns_name
        dns_without_scheme = dns_without_scheme.lstrip("/").rstrip("/")
        login_token_refresh_url = f"https://{dns_without_scheme}/.well-known/jwks.json"

        oauth_provider_info = self.oauth.get_provider_info()
        if not oauth_provider_info:
            logger.warning("OAuth provider info is not ready yet")
            self.unit.status = BlockedStatus("Waiting for OAuth provider info")
            return
        known_scopes = set(OAUTH_SCOPES.split(" "))
        oauth_provider_scopes = set(oauth_provider_info.scope.split(" "))
        scopes = " ".join(sorted(oauth_provider_scopes.intersection(known_scopes)))

        try:
            session_key = self.model.get_secret(label=SESSION_KEY_SECRET_LABEL).get_content()[SESSION_KEY_LOOKUP]
        except SecretNotFoundError:
            logger.warning("session key secret not found, deferring")
            event.defer()
            return

        try:
            host_key = self._get_host_key()
        except Exception as e:
            logger.warning(f"error retrieving host-key: {e}, deferring...")
            self.unit.status = BlockedStatus("hostkey retrieval failed. Check juju debug logs.")
            event.defer()
            return

        jwks_config = self._jwks_config()
        if not jwks_config:
            logger.warning("JWKS secret is not ready yet")
            self.unit.status = BlockedStatus("Waiting for JWKS secret")
            event.defer()
            return

        # Update the ssh ingress to reflect ssh port config changed. This is done in the leader unit
        # because the ingress is per-unit and it doesn't support multiple units.
        if self.unit.is_leader():
            self.ingress_ssh.provide_ingress_requirements(port=self._ssh_port)

        config_values = {
            "BAKERY_PRIVATE_KEY": self.config.get("private-key", ""),
            "BAKERY_PUBLIC_KEY": self.config.get("public-key", ""),
            "CORS_ALLOWED_ORIGINS": self.config.get("cors-allowed-origins"),
            "HTTP_PROXY": os.environ.get("JUJU_CHARM_HTTP_PROXY"),
            "HTTPS_PROXY": os.environ.get("JUJU_CHARM_HTTPS_PROXY"),
            "JIMM_ACCESS_TOKEN_EXPIRY_DURATION": self.config.get("session-expiry-duration"),
            "JIMM_ADMINS": self.config.get("controller-admins", ""),
            "JIMM_AUDIT_LOG_RETENTION_PERIOD_IN_DAYS": self.config.get("audit-log-retention-period-in-days", ""),
            "JIMM_BOOTSTRAP_LOGIN_TOKEN_REFRESH_URL": login_token_refresh_url,
            "JIMM_DASHBOARD_FINAL_REDIRECT_URL": self.config.get("juju-dashboard-location"),
            "JIMM_DASHBOARD_LOCATION": self.config.get("juju-dashboard-location", "https://jaas.ai/models"),
            "JIMM_DNS_NAME": dns_name,
            "JIMM_DSN": self._make_database_dsn(),
            "JIMM_JWT_EXPIRY": self.config.get("jwt-expiry"),
            "JIMM_JWKS": jwks_config["jwks"],
            "JIMM_JWKS_CACHE_MAX_AGE": str(JWKS_CACHE_MAX_AGE),
            "JIMM_JWKS_PRIVATE_KEY": jwks_config["private_key"],
            "JIMM_LISTEN_ADDR": ":8080",
            "JIMM_INTERNAL_LISTEN_ADDR": ":9090",
            "JIMM_LOG_LEVEL": self.config.get("log-level", ""),
            "JIMM_MACAROON_EXPIRY_DURATION": self.config.get("macaroon-expiry-duration", "24h"),
            "JIMM_OAUTH_CLIENT_ID": oauth_provider_info.client_id,
            "JIMM_OAUTH_CLIENT_SECRET": oauth_provider_info.client_secret,
            "JIMM_OAUTH_ISSUER_URL": oauth_provider_info.issuer_url,
            "JIMM_OAUTH_SCOPES": scopes,
            "JIMM_SECURE_SESSION_COOKIES": self.config.get("secure-session-cookies"),
            "JIMM_SESSION_COOKIE_MAX_AGE": self.config.get("session-cookie-max-age"),
            "JIMM_SESSION_SECRET_KEY": session_key,
            "JIMM_SSH_HOST_KEY": host_key,
            "JIMM_SSH_MAX_CONCURRENT_CONNECTIONS": self.config.get("ssh-max-concurrent-connections"),
            "JIMM_SSH_PORT": self.config.get("ssh-port"),
            "JIMM_UUID": self.config.get("uuid", ""),
            "NO_PROXY": os.environ.get("JUJU_CHARM_NO_PROXY"),
            "OPENFGA_AUTH_MODEL": self._state.openfga_auth_model_id,
            "OPENFGA_HOST": openfga_url_details.hostname,
            "OPENFGA_PORT": openfga_url_details.port,
            "OPENFGA_SCHEME": openfga_url_details.scheme,
            "OPENFGA_STORE": openfga_info.store_id,
            "OPENFGA_TOKEN": openfga_info.token,
        }
        if self.unit.is_leader():
            config_values["JIMM_IS_LEADER"] = "True"

        vault_config = self._vault_config()
        insecure_secret_store = self.config.get("postgres-secret-storage", False)
        if not vault_config and not insecure_secret_store:
            logger.warning("Vault relation is not ready yet")
            self.unit.status = BlockedStatus("Waiting for Vault relation")
            return
        elif vault_config and not insecure_secret_store:
            config_values.update(vault_config)

        if self.config.get("postgres-secret-storage", False):
            config_values["INSECURE_SECRET_STORAGE"] = "true"  # Parsed by Go's strconv.ParseBool

        # remove empty configuration values
        config_values = {key: value for key, value in config_values.items() if value}

        pebble_layer: pebble.LayerDict = {
            "summary": "jimm layer",
            "description": "pebble config layer for jimm",
            "services": {
                JIMM_SERVICE_NAME: {
                    "override": "replace",
                    "summary": "JAAS Intelligent Model Manager",
                    "command": "/usr/local/bin/jimmsrv",
                    "startup": "disabled",
                    "environment": config_values,
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
        force_restart = self._update_trusted_ca_certs(container)
        container.add_layer("jimm", pebble_layer, combine=True)
        try:
            if self._ready():
                if container.get_service(JIMM_SERVICE_NAME).is_running():
                    if force_restart:
                        logger.info("performing service restart")
                        container.restart(JIMM_SERVICE_NAME)
                    else:
                        logger.info("replanning service")
                        container.replan()
                else:
                    logger.info("starting service")
                    container.start(JIMM_SERVICE_NAME)
                self.unit.status = ActiveStatus("running")
                if self.unit.is_leader():
                    self.app.status = ActiveStatus()
            else:
                logger.info("workload not ready - returning")
                return
        except DeferError:
            logger.info("workload container not ready - deferring")
            event.defer()
            return

        dashboard_relation = self.model.get_relation("dashboard")
        if dashboard_relation and self.unit.is_leader():
            dashboard_relation.data[self.app].update(
                {
                    "controller-url": "wss://{}".format(dns_name),
                    "is-juju": str(False),
                }
            )

    def ensure_session_secret_key(self):
        if not self.unit.is_leader():
            return
        try:
            self.model.get_secret(label=SESSION_KEY_SECRET_LABEL)
        except SecretNotFoundError:
            self.app.add_secret(new_session_key(), label=SESSION_KEY_SECRET_LABEL)

    def ensure_jwks_secret_key(self) -> None:
        if not self.unit.is_leader() or not self._state.is_ready():
            return
        # The leader owns key generation and publishes the current secret ids through peer data.
        self._reconcile_jwks_secrets()

    def rotate_session_secret_key(self, event: ActionEvent):
        if not self.unit.is_leader():
            event.log("Cannot update secret from non-leader unit")
            event.fail("Run this action on the leader unit")
            return
        secret = self.model.get_secret(label=SESSION_KEY_SECRET_LABEL)
        secret.set_content(new_session_key())
        # Force a refresh of the secret content to flush old data.
        secret.get_content(refresh=True)
        try:
            self._update_workload(event)
        except RuntimeError:
            # This exception will be raised when trying to defer the action event.
            warning_msg = "updating workload failed, JIMM units weren't restarted, they might not be ready"
            logger.warning(warning_msg)
            event.log(warning_msg)

    # Ensure the host key is present.
    def ensure_hostkey_secret_key(self):
        if not self.unit.is_leader():
            return
        try:
            self.model.get_secret(label=HOST_KEY_SECRET_LABEL)
        except SecretNotFoundError:
            self.app.add_secret(new_host_key(), label=HOST_KEY_SECRET_LABEL)

    def on_secret_changed(self, event: SecretChangedEvent):
        """
        Fired on all units observing a secret after the owner of a secret has published a new revision.
        We must ensure the secret content is refreshed either here or where we fetch the secret.
        """
        event.secret.get_content(refresh=True)
        self._update_workload(event)

    def _on_start(self, event):
        """Start JIMM."""
        self._update_workload(event)

    def _on_stop(self, _) -> None:
        """Stop JIMM."""
        self._stop()
        try:
            self._ready()
        except DeferError:
            logger.info("workload not ready")
            return

    def _stop(self):
        try:
            container = self.unit.get_container(WORKLOAD_CONTAINER)
            if container.can_connect() and container.get_service(JIMM_SERVICE_NAME).is_running():
                container.stop(JIMM_SERVICE_NAME)
        except Exception as e:
            logger.error("failed to stop the jimm service: {}".format(e))

    def _on_update_status(self, event) -> None:
        """Update the status of the charm."""
        if self.unit.is_leader() and self._state.is_ready():
            self._reconcile_jwks_secrets()

        # update vault relation if exists
        binding = self.model.get_binding("vault-kv")
        if binding is not None:
            try:
                egress_subnets = self._egress_subnets(binding)
                self.vault.request_credentials(event.relation, egress_subnets, self.get_vault_nonce())
            except Exception as e:
                logger.warning(f"failed to update vault relation - {repr(e)}")

        self._update_workload(event)

    @requires_state_setter
    def _on_dashboard_relation_joined(self, event: RelationJoinedEvent) -> None:
        dns_name = self._get_dns_name(event)
        if not dns_name:
            return

        event.relation.data[self.app].update(
            {
                "controller-url": "wss://{}".format(dns_name),
                "is-juju": str(False),
            }
        )

    @requires_state_setter
    def _on_database_event(self, event: DatabaseRequiresEvent) -> None:
        """Database event handler."""

        logger.info("received database event")
        self._update_workload(event)

    @requires_state_setter
    def _on_database_relation_broken(self, event: RelationDepartedEvent) -> None:
        """Database relation broken event handler."""

        self._update_workload(event)

    def _make_database_dsn(self) -> str:
        """Constructs a database DSN from the database relation."""
        if not self.database.is_resource_created():
            return ""

        integration_id = self.database.relations[0].id
        integration_data: dict[str, str] = self.database.fetch_relation_data()[integration_id]
        username = integration_data.get("username", "")
        password = integration_data.get("password", "")
        endpoint = integration_data.get("endpoints", "").split(",")[0]
        return f"postgresql://{username}:{password}@{endpoint}/{DATABASE_NAME}"

    def _ready(self):
        container = self.unit.get_container(WORKLOAD_CONTAINER)

        if container.can_connect():
            plan = container.get_plan()
            service = plan.services.get(JIMM_SERVICE_NAME)
            if service is None:
                logger.warning("waiting for service")
                if self.unit.status.message == "":
                    self.unit.status = WaitingStatus("waiting for service")
                return False

            env_vars = service.environment

            for setting, message in REQUIRED_SETTINGS.items():
                if not env_vars.get(setting, ""):
                    self.unit.status = BlockedStatus(
                        "{} configuration value not set: {}".format(setting, message),
                    )
                    return False

            if container.get_service(JIMM_SERVICE_NAME).is_running():
                self.unit.status = ActiveStatus("running")
            else:
                self.unit.status = WaitingStatus("stopped")
            return True
        else:
            raise DeferError

    def _on_vault_connected(self, event: vault_kv.VaultKvConnectedEvent):
        relation = self.model.get_relation(event.relation_name, event.relation_id)
        if relation is None:
            logger.warning("vault relation missing during connected event")
            return
        egress_subnets = self._egress_subnets(self.model.get_binding(relation))
        self.vault.request_credentials(relation, egress_subnets, self.get_vault_nonce())

    def _on_vault_ready(self, event: vault_kv.VaultKvReadyEvent) -> None:
        self._update_workload(event)

    def _on_vault_gone_away(self, event: vault_kv.VaultKvGoneAwayEvent) -> None:
        self._update_workload(event)

    @requires_state_setter
    def _on_openfga_store_created(self, event: OpenFGAStoreCreateEvent) -> None:
        self._update_workload(event)

    @requires_state
    def _get_dns_name(self, event) -> str:
        return self.ingress.url or str(self.config.get("dns-name", ""))

    def _get_host_key(self) -> str:
        """
        _get_host_key gets the host key from the user's secret set in the charm config if set or from the default secret
        created by the charm.
        """
        host_key_secret_id = str(self.config.get("ssh-host-key-secret-id", ""))
        if not host_key_secret_id:
            host_key = self.model.get_secret(label=HOST_KEY_SECRET_LABEL).get_content(refresh=True)[HOST_KEY_LOOKUP]
        else:
            host_key = self.model.get_secret(id=host_key_secret_id).get_content(refresh=True)[HOST_KEY_LOOKUP]

        if not is_valid_private_key(host_key):
            raise ValueError("Invalid private key")

        return host_key

    @requires_state_setter
    def _on_certificates_relation_joined(self, event: RelationJoinedEvent) -> None:
        dns_name = self._get_dns_name(event)
        if not dns_name:
            logger.warning("missing dns name, won't generate csr")
            return

        csr = generate_csr(
            private_key=self._state.private_key.encode(),
            subject=dns_name,
        )

        self._state.csr = csr.decode().removesuffix("\n")

        self.certificates.request_certificate_creation(certificate_signing_request=csr)

    @requires_state_setter
    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        self._state.certificate = event.certificate
        self._state.ca = event.ca
        self._state.chain = event.chain

        self._update_workload(event)

    @requires_state_setter
    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        old_csr = self._state.csr
        private_key = self._state.private_key
        dns_name = self._get_dns_name(event)
        if not dns_name:
            return

        new_csr = generate_csr(
            private_key=private_key.encode(),
            subject=dns_name,
        )
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr,
            new_certificate_signing_request=new_csr,
        )
        self._state.csr = new_csr.decode()

        self._update_workload(event)

    @requires_state_setter
    def _on_certificate_revoked(self, event: CertificateRevokedEvent) -> None:
        old_csr = self._state.csr
        private_key = self._state.private_key
        dns_name = self._get_dns_name(event)
        if not dns_name:
            return

        new_csr = generate_csr(
            private_key=private_key.encode(),
            subject=dns_name,
        )
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr,
            new_certificate_signing_request=new_csr,
        )

        self._state.csr = new_csr.decode()
        del self._state.certificate
        del self._state.ca
        del self._state.chain

        self.unit.status = WaitingStatus("Waiting for new certificate")
        self._update_workload(event)

    @requires_state_setter
    def _on_ingress_ready(self, event: IngressPerAppReadyEvent) -> None:
        logger.info(f"Ingress for HTTP/S at {event.url}")

        self._update_workload(event)

    def _on_ingress_ssh_ready(self, event: IngressPerUnitReadyForUnitEvent):
        logger.info(f"Ingress for SSH at {event.url}")

    def _on_ingress_ssh_revoked(self, _):
        logger.info("This app no longer has SSH ingress")

    @requires_state_setter
    def _on_ingress_revoked(self, event: IngressPerAppRevokedEvent) -> None:
        logger.info("This app no longer has HTTP/S ingress")

        self._update_workload(event)

    @requires_state
    def setup_fga_auth_model(self, jimm_container: Container) -> None:
        """Creates the OpenFGA authorisation model using an auth model found inside the OCI image.

        Args:
            jimm_container (Container): Workload container to connect to.

        Raises:
            LookupError: Raised when the auth model file is not found in the container.
            ValueError: Raised when the auth model is empty.
            ValueError: Raised when the auth model create request fails.
            ValueError: Raised when the auth model create response does not contain a model ID.
        """
        if not self.unit.is_leader():
            return

        model_path = "/root/openfga/authorisation_model.json"
        try:
            auth_model = jimm_container.pull(model_path).read()
        except pebble.PathError:
            logger.warning("auth model not found at %s", model_path)
            raise LookupError("Failed to find auth model in JIMM's OCI image")

        if not auth_model:
            raise ValueError("empty auth model found")

        info = self.openfga.get_store_info()
        if not info:
            logger.warning("openfga is not ready yet, skipping auth model creation")
            return

        # Ensure store_id exists before continuing
        if not info.store_id:
            logger.warning("openfga store_id not available yet; skipping auth model setup")
            return

        # Use client for OpenFGA interactions
        client = OpenFGAClient(info.http_api_url, info.store_id, token=info.token, verify=False)
        local_model = json.loads(auth_model)

        # First check if the auth model already exists in OpenFGA.
        auth_model_id = self._state.openfga_auth_model_id
        auth_model_exists = False
        if auth_model_id:
            logger.info("checking existing OpenFGA authorization model")
            try:
                remote = client.get_authorization_model(auth_model_id)
            except ValueError as e:
                logger.error("failed to fetch existing authorization model: %s", e)
                logger.warning("skipping auth model creation")
                return
            if remote is not None:
                logger.info("found OpenFGA authorisation model")
                auth_model_exists = True

        # Compare auth model from the image with the one in the state
        # See https://github.com/openfga/openfga/issues/2277 for more info.
        model_hash = hashlib.new("md5")
        model_hash.update(auth_model.encode())
        digest = model_hash.hexdigest()
        if auth_model_exists and self._state.openfga_auth_model_digest == digest:
            logger.info("OpenFGA authorisation model already exists and is up to date")
            return

        # Create/Update the authorization model
        logger.info("OpenFGA authorisation model changed; updating")
        try:
            authorization_model_id = client.create_authorization_model(local_model)
        except ValueError as e:
            logger.warning("failed to create OpenFGA authorisation model: %s", e)
            logger.warning("skipping auth model creation; will retry on next event")
            return
        if not authorization_model_id:
            logger.error("response does not contain authorization model id")
            raise ValueError("response does not contain authorization model id")
        self._state.openfga_auth_model_id = authorization_model_id
        self._state.openfga_auth_model_digest = digest

    @property
    def _oauth_client_config(self) -> ClientConfig:
        dns = self._get_dns_name(None)
        if dns is None or dns == "":
            dns = "http://localhost"
        dns = ensureFQDN(str(dns))
        dns = ensureAbsoluteURL(dns)
        return ClientConfig(
            redirect_uri=urljoin(dns, "auth/callback"),
            scope=OAUTH_SCOPES,
            grant_types=OAUTH_GRANT_TYPES,
            token_endpoint_auth_method="client_secret_post",
        )

    def get_vault_nonce(self) -> str:
        secret = self.model.get_secret(label=VAULT_NONCE_SECRET_LABEL)
        nonce = secret.get_content(refresh=True)["nonce"]
        return nonce

    def _update_trusted_ca_certs(self, container: Container) -> bool:
        """This function receives the trusted certificates from the certificate_transfer integration.

        JIMM needs to restart to use newly received certificates. Certificates attached to the
        relation need to be pulled before JIMM is started.
        This function is needed because relation events are not emitted on upgrade, and because we
        do not have (nor do we want) persistent storage for certs.

        Args:
            container (Container): The workload container, the caller must ensure that we can connect.

        Returns:
            bool: A boolean to indicate whether the workload service should be restarted.
        """
        if not self.model.get_relation(relation_name=self.trusted_cert_transfer.relationship_name):
            return False

        logger.info("Validating trusted ca certificates.")

        ca_certs = self.trusted_cert_transfer.get_all_certificates()

        # deal with v0 relations
        cert_transfer_integrations = self.trusted_cert_transfer.charm.model.relations[
            CERTIFICATE_TRANSFER_INTEGRATION_NAME
        ]

        for integration in cert_transfer_integrations:
            ca = {integration.data[unit]["ca"] for unit in integration.units if "ca" in integration.data.get(unit, {})}
            ca_certs.update(ca)

        ca_bundle = "\n".join(ca_certs)

        if not ca_certs:
            logger.info("No trusted CA certificates found, skipping update.")
            return False

        ca_bundle = "\n".join(sorted(ca_certs))

        try:
            existing_ca_bundle = container.pull(TRUSTED_CA_PATH).read()
        except pebble.PathError:
            existing_ca_bundle = ""

        if existing_ca_bundle == ca_bundle:
            logger.info("Existing certificates match, no update needed.")
            return False

        logger.warning("Existing certificates do not match, updating...")
        container.push(TRUSTED_CA_PATH, ca_bundle, make_dirs=True)

        stdout, stderr = container.exec(["update-ca-certificates", "--fresh"]).wait_output()
        logger.info("stdout update-ca-certificates: %s", stdout)
        logger.info("stderr update-ca-certificates: %s", stderr)
        return True

    def _on_trusted_certificate_available(self, event: CertificatesAvailableEvent) -> None:
        self._update_workload(event)

    def _on_trusted_certificate_removed(self, event: CertificatesRemovedEvent) -> None:
        self._update_workload(event)

    def _egress_subnets(self, binding: Binding | None) -> list[str]:
        if binding:
            # Here we capture the subnets that other units will see the charm connecting from
            # and can be modified by setting the --via flag when performing relations.
            subnets = [str(subnet) for subnet in binding.network.egress_subnets[0].subnets()]
            # This additional subnet is the subnet of the current charm network, useful when
            # connection to Vault deployed in the same k8s cluster as JIMM.
            subnets.append(str(binding.network.interfaces[0].subnet))
            return subnets
        raise ValueError("unknown egress subnet")

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _jwks_config(self) -> dict[str, str] | None:
        """Return the currently published JWKS payload and active signing key.

        The returned JWKS contains every public key that should still be advertised,
        including any pre-rotated key during the overlap window. The private key is
        always taken from the newest key whose activation time has passed. This
        method is read-only; leader hooks reconcile the secret lifecycle separately.
        Returns ``None`` until the charm has enough secret state to configure the
        workload.
        """
        secret_ids = list(self._state.jwks_secret_ids or [])
        if not secret_ids:
            return None

        secrets = self._load_jwks_secrets(secret_ids, refresh=True)
        if not secrets:
            return None

        now = self._now()
        # Every extant key is published until expiry.
        published = sorted(
            [secret for secret in secrets if now < secret.expires_at],
            key=lambda secret: secret.activate_at,
        )
        if not published:
            return None

        active = [secret for secret in published if secret.activate_at <= now]
        if not active:
            return None

        # JIMM signs with the newest active key but serves every still-published public key.
        jwks = json.dumps({"keys": [secret.public_jwk for secret in published]}, separators=(",", ":"))
        return {"jwks": jwks, "private_key": active[-1].private_key}

    def _reconcile_jwks_secrets(self) -> None:
        """Progress JWKS signing keys through their lifecycle and publish the active set of public keys.

        JWKS rotation keeps one Juju secret per signing key and moves each key through
        four phases. First, the leader seeds or pre-publishes a key so its public JWK
        appears in the JWKS document. Second, after the propagation delay, that key
        becomes the active signer while older public keys may still be advertised.
        Third, once a newer key is active, older public keys remain published until
        their original expiry time so recently issued tokens can still be validated.
        Finally, once a key expires, it is removed.
        """
        secret_ids = list(self._state.jwks_secret_ids or [])
        now = self._now()
        existing = self._load_jwks_secrets(secret_ids, refresh=True)

        if not existing:
            # Seed the very first signing key immediately so the workload can start.
            secret = self._create_jwks_secret(now)
            self._state.jwks_secret_ids = [secret.id]
            return

        latest = max(existing, key=lambda secret: secret.activate_at)
        future = [secret for secret in existing if secret.activate_at > now]
        changed = False

        pre_rotation_starts_at = latest.expires_at - JWKS_PRE_ROTATION_INTERVAL
        if now >= pre_rotation_starts_at and not future:
            # Prepublish the next key, ensuring we wait >> the advertised cache
            # duration before allowing it to become the active signing key.
            activate_at = now + JWKS_PROPAGATION_DELAY
            secret = self._create_jwks_secret(activate_at)
            secret_ids.append(secret.id)
            changed = True

        retained_ids: list[str] = []
        current = {secret.secret_id: secret for secret in self._load_jwks_secrets(secret_ids, refresh=True)}
        for secret_id in secret_ids:
            secret = current.get(secret_id)
            if secret is None:
                changed = True
                continue
            if secret.expires_at <= now:
                # Once a key has expired, remove the old Juju secret entirely.
                secret.secret.remove_all_revisions()
                changed = True
                continue
            retained_ids.append(secret_id)

        if changed or retained_ids != list(self._state.jwks_secret_ids or []):
            self._state.jwks_secret_ids = retained_ids

    def _create_jwks_secret(self, activate_at: datetime):
        content = new_jwks_secret(activate_at)
        return self.app.add_secret(content, label=f"{JWKS_SECRET_LABEL_PREFIX}{content[JWKS_KID_LOOKUP]}")

    def _load_jwks_secrets(self, secret_ids: list[str], refresh: bool) -> list[JWKSSecret]:
        secrets: list[JWKSSecret] = []
        for secret_id in secret_ids:
            try:
                secret = self.model.get_secret(id=secret_id)
                content = secret.get_content(refresh=refresh)
            except SecretNotFoundError:
                continue
            if secret.id is None:
                continue
            secrets.append(
                JWKSSecret(
                    activate_at=_parse_datetime(content[JWKS_ACTIVATE_AT_LOOKUP]),
                    expires_at=_parse_datetime(content[JWKS_EXPIRES_AT_LOOKUP]),
                    kid=content[JWKS_KID_LOOKUP],
                    private_key=content[JWKS_PRIVATE_KEY_LOOKUP],
                    public_jwk=json.loads(content[JWKS_PUBLIC_JWK_LOOKUP]),
                    secret=secret,
                    secret_id=secret.id,
                )
            )
        return secrets


def new_session_key():
    """Generate a session secret dict which holds a key value pair used for securing session tokens."""
    return {SESSION_KEY_LOOKUP: b64encode(os.urandom(64)).decode("utf-8")}


def new_host_key():
    """Generate a host key dict which holds a key value pair used for securing SSH connections.
    The key is a 4096 bit RSA key generated using the charm's tls_certificates library using.
    """
    return {HOST_KEY_LOOKUP: generate_private_key(key_size=4096).decode()}


def new_jwks_secret(activate_at: datetime) -> dict[str, str]:
    # Each Juju secret stores one signing key plus its activate/expiry timestamps.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_numbers = private_key.public_key().public_numbers()
    kid = str(uuid4())
    public_jwk = {
        "alg": "RS256",
        "e": _base64url_uint(public_numbers.e),
        "kid": kid,
        "kty": "RSA",
        "n": _base64url_uint(public_numbers.n),
        "use": "sig",
    }
    expires_at = activate_at + JWKS_ROTATION_PERIOD
    return {
        JWKS_ACTIVATE_AT_LOOKUP: _format_datetime(activate_at),
        JWKS_EXPIRES_AT_LOOKUP: _format_datetime(expires_at),
        JWKS_KID_LOOKUP: kid,
        JWKS_PRIVATE_KEY_LOOKUP: private_pem,
        JWKS_PUBLIC_JWK_LOOKUP: json.dumps(public_jwk, separators=(",", ":"), sort_keys=True),
    }


def _base64url_uint(value: int) -> str:
    """Encode an unsigned integer using the JWK Base64urlUInt format.

    RSA JWK members such as ``n`` and ``e`` are serialized as base64url-
    encoded big-endian bytes without ``=`` padding, not as decimal strings.
    """
    length = max(1, (value.bit_length() + 7) // 8)
    return urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def _format_datetime(value: datetime) -> str:
    """Return a UTC ISO 8601 timestamp using ``Z`` for the UTC offset.

    The charm stores JWKS lifecycle timestamps in secrets using the compact
    ``...Z`` form and round-trips them with :func:`_parse_datetime`.
    """
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    """Parse a stored ISO 8601 timestamp and normalize it to UTC.

    Secret data uses ``Z`` to denote UTC, while ``fromisoformat`` is more
    consistent with ``+00:00``, so normalize first and return an aware UTC
    datetime.
    """
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def ensureFQDN(dns: str) -> str:  # noqa: N802
    """Ensures a domain name has an https:// prefix."""
    if not dns.startswith("http"):
        dns = "https://" + dns
    return dns


def ensureAbsoluteURL(dns: str) -> str:  # noqa: N802
    """
    Ensures a domain name has a trailing slash.
    This prevents methods like urljoin from stripping path components.
    """
    if not dns.endswith("/"):
        dns = dns + "/"
    return dns


def is_valid_private_key(key: str):
    """
    is_valid_private_key checks if the provided key is a valid private key, either PEM or OPENSSH format.
    """
    try:
        serialization.load_pem_private_key(key.encode(), password=None)
        return True
    except Exception:
        try:
            serialization.load_ssh_private_key(key.encode(), password=None)
            return True
        except Exception as e:
            logger.error(f"Invalid private key: {e}")
            return False


if __name__ == "__main__":
    main(JimmOperatorCharm)
