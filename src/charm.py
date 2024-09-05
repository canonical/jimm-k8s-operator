#!/usr/bin/env python3
# This file is part of the JIMM k8s Charm for Juju.
# Copyright 2024 Canonical Ltd.

import hashlib
import json
import logging
import os
import secrets
import string
from base64 import b64encode
from urllib.parse import urljoin, urlparse

import requests
from charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateRemovedEvent,
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
from charms.traefik_k8s.v1.ingress import (
    IngressPerAppReadyEvent,
    IngressPerAppRequirer,
    IngressPerAppRevokedEvent,
)
from charms.vault_k8s.v0 import vault_kv
from ops import pebble
from ops.charm import (
    ActionEvent,
    CharmBase,
    InstallEvent,
    RelationJoinedEvent,
    SecretChangedEvent,
)
from ops.main import main
from ops.model import (
    ActiveStatus,
    Binding,
    BlockedStatus,
    Container,
    ErrorStatus,
    SecretNotFoundError,
    TooManyRelatedAppsError,
    WaitingStatus,
)

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
TRUSTED_CA_TEMPLATE = string.Template("/usr/local/share/ca-certificates/trusted-ca-cert-$rel_id-ca.crt")
SESSION_KEY_SECRET_LABEL = "session_key"
# Keys should be lowercase letters and digits, at least 3 characters long,
# start with a letter, and not start or end with a hyphen.
SESSION_KEY_LOOKUP = "sessionkey"


class DeferError(Exception):
    """Used to indicate to the calling function that an event could be deferred
    if the hook needs to be retried."""

    pass


class JimmOperatorCharm(CharmBase):
    """JIMM Operator Charm."""

    def __init__(self, *args):
        super().__init__(*args)

        self._state = State(self.app, lambda: self.model.get_relation("peer"))
        self.oauth = OAuthRequirer(self, self._oauth_client_config, relation_name=OAUTH)

        self.framework.observe(self.oauth.on.oauth_info_changed, self._on_oauth_info_changed)
        self.framework.observe(self.oauth.on.oauth_info_removed, self._on_oauth_info_changed)
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

        # Traefik ingress relation
        self.ingress = IngressPerAppRequirer(
            self,
            relation_name="ingress",
            port=8080,
        )
        self.framework.observe(self.ingress.on.ready, self._on_ingress_ready)
        self.framework.observe(
            self.ingress.on.revoked,
            self._on_ingress_revoked,
        )

        # Nginx ingress relation
        require_nginx_route(
            charm=self, service_hostname=self.config.get("dns-name", ""), service_name=self.app.name, service_port=8080
        )

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
        self.framework.observe(self.vault.on.connected, self._on_vault_connected)
        self.framework.observe(self.vault.on.ready, self._on_vault_ready)
        self.framework.observe(self.vault.on.gone_away, self._on_vault_gone_away)

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

        self.trusted_cert_transfer = CertificateTransferRequires(self, "receive-ca-cert")
        self.framework.observe(
            self.trusted_cert_transfer.on.certificate_available,
            self._on_trusted_certificate_available,  # pyright: ignore
        )
        self.framework.observe(
            self.trusted_cert_transfer.on.certificate_removed,
            self._on_trusted_certificate_removed,  # pyright: ignore
        )

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

    @requires_state_setter
    def _on_leader_elected(self, event) -> None:
        if not self._state.private_key:
            private_key: bytes = generate_private_key(key_size=4096)
            self._state.private_key = private_key.decode()

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

        self.oauth.update_client_config(client_config=self._oauth_client_config)
        if not self.oauth.is_client_created():
            logger.warning("OAuth relation is not ready yet")
            self.unit.status = BlockedStatus("Waiting for OAuth relation")
            return

        self.setup_fga_auth_model(container)

        dns_name = self._get_dns_name(event)
        if not dns_name:
            logger.warning("dns name not set")
            return

        oauth_provider_info = self.oauth.get_provider_info()
        known_scopes = set(OAUTH_SCOPES.split(" "))
        oauth_provider_scopes = set(oauth_provider_info.scope.split(" "))
        scopes = " ".join(sorted(oauth_provider_scopes.intersection(known_scopes)))

        try:
            session_key = self.model.get_secret(label=SESSION_KEY_SECRET_LABEL).get_content()[SESSION_KEY_LOOKUP]
        except SecretNotFoundError:
            logger.warning("session key secret not found, deferring")
            event.defer()
            return

        config_values = {
            "CORS_ALLOWED_ORIGINS": self.config.get("cors-allowed-origins"),
            "JIMM_AUDIT_LOG_RETENTION_PERIOD_IN_DAYS": self.config.get("audit-log-retention-period-in-days", ""),
            "JIMM_ADMINS": self.config.get("controller-admins", ""),
            "JIMM_DNS_NAME": dns_name,
            "JIMM_LOG_LEVEL": self.config.get("log-level", ""),
            "JIMM_UUID": self.config.get("uuid", ""),
            "JIMM_DASHBOARD_LOCATION": self.config.get("juju-dashboard-location", "https://jaas.ai/models"),
            "JIMM_LISTEN_ADDR": ":8080",
            "OPENFGA_STORE": self._state.openfga_store_id,
            "OPENFGA_AUTH_MODEL": self._state.openfga_auth_model_id,
            "OPENFGA_HOST": self._state.openfga_address,
            "OPENFGA_SCHEME": self._state.openfga_scheme,
            "OPENFGA_TOKEN": self._state.openfga_token,
            "OPENFGA_PORT": self._state.openfga_port,
            "BAKERY_PRIVATE_KEY": self.config.get("private-key", ""),
            "BAKERY_PUBLIC_KEY": self.config.get("public-key", ""),
            "JIMM_JWT_EXPIRY": self.config.get("jwt-expiry"),
            "JIMM_MACAROON_EXPIRY_DURATION": self.config.get("macaroon-expiry-duration", "24h"),
            "JIMM_ACCESS_TOKEN_EXPIRY_DURATION": self.config.get("session-expiry-duration"),
            "JIMM_OAUTH_ISSUER_URL": oauth_provider_info.issuer_url,
            "JIMM_OAUTH_CLIENT_ID": oauth_provider_info.client_id,
            "JIMM_OAUTH_CLIENT_SECRET": oauth_provider_info.client_secret,
            "JIMM_OAUTH_SCOPES": scopes,
            "JIMM_DASHBOARD_FINAL_REDIRECT_URL": self.config.get("juju-dashboard-location"),
            "JIMM_SECURE_SESSION_COOKIES": self.config.get("secure-session-cookies"),
            "JIMM_SESSION_COOKIE_MAX_AGE": self.config.get("session-cookie-max-age"),
            "JIMM_SESSION_SECRET_KEY": session_key,
            "NO_PROXY": os.environ.get("JUJU_CHARM_NO_PROXY"),
            "HTTP_PROXY": os.environ.get("JUJU_CHARM_HTTP_PROXY"),
            "HTTPS_PROXY": os.environ.get("JUJU_CHARM_HTTPS_PROXY"),
        }
        if self.unit.is_leader():
            config_values["JIMM_IS_LEADER"] = "True"

        if self._state.dsn:
            config_values["JIMM_DSN"] = self._state.dsn

        vault_config = self._vault_config()
        insecure_secret_store = self.config.get("postgres-secret-storage", False)
        if not vault_config and not insecure_secret_store:
            logger.warning("Vault relation is not ready yet")
            self.unit.status = BlockedStatus("Waiting for Vault relation")
            return
        elif vault_config and not insecure_secret_store:
            config_values.update(vault_config)

        if self.config.get("postgres-secret-storage", False):
            config_values["INSECURE_SECRET_STORAGE"] = "enabled"  # Value doesn't matter, checks env var exists.

        # remove empty configuration values
        config_values = {key: value for key, value in config_values.items() if value}

        pebble_layer = {
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
                    "controller_url": "wss://{}".format(dns_name),
                    "is_juju": str(False),
                }
            )

    def ensure_session_secret_key(self):
        if not self.unit.is_leader():
            return
        try:
            self.model.get_secret(label=SESSION_KEY_SECRET_LABEL)
        except SecretNotFoundError:
            self.app.add_secret(new_session_key(), label=SESSION_KEY_SECRET_LABEL)

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

    def on_secret_changed(self, event: SecretChangedEvent):
        """
        Fired on all units observing a secret after the owner of a secret has published a new revision.
        We must ensure the secret content is refreshed either here or where we fetch the secret.
        """
        # Force a refresh of the secret content to flush old data.
        self.model.get_secret(label=SESSION_KEY_SECRET_LABEL).get_content(refresh=True)
        self._update_workload(event)

    def _on_start(self, event):
        """Start JIMM."""
        self._update_workload(event)

    def _on_stop(self, _) -> None:
        """Stop JIMM."""
        try:
            container = self.unit.get_container(WORKLOAD_CONTAINER)
            if container.can_connect():
                container.stop(JIMM_SERVICE_NAME)
        except Exception as e:
            logger.info("failed to stop the jimm service: {}".format(e))
        try:
            self._ready()
        except DeferError:
            logger.info("workload not ready")
            return

    def _on_update_status(self, event) -> None:
        """Update the status of the charm."""
        if self.unit.status.name == ErrorStatus.name:
            # Skip ready check if unit in error to allow for error resolution.
            logger.info("unit in error status, skipping ready check")
            return

        try:
            self._ready()
        except DeferError:
            logger.info("workload not ready")
            return

        # update vault relation if exists
        binding = self.model.get_binding("vault-kv")
        if binding is not None:
            try:
                egress_subnets = self._egress_subnets(binding)
                self.vault.request_credentials(event.relation, egress_subnets, self.get_vault_nonce())
            except Exception as e:
                logger.warning(f"failed to update vault relation - {repr(e)}")

    @requires_state_setter
    def _on_dashboard_relation_joined(self, event: RelationJoinedEvent) -> None:
        dns_name = self._get_dns_name(event)
        if not dns_name:
            return

        event.relation.data[self.app].update(
            {
                "controller_url": "wss://{}".format(dns_name),
                "is_juju": str(False),
            }
        )

    @requires_state_setter
    def _on_database_event(self, event: DatabaseRequiresEvent) -> None:
        """Database event handler."""

        if event.username is None or event.password is None:
            logger.info(
                "(postgresql) Relation data is not complete (missing `username` or `password` field); "
                "returning early. This hook should retriggered later."
            )
            return

        # get the first endpoint from a comma separate list
        ep = event.endpoints.split(",", 1)[0]
        # compose the db connection string
        uri = f"postgresql://{event.username}:{event.password}@{ep}/{DATABASE_NAME}"

        logger.info("received database uri: {}".format(uri))

        # record the connection string
        self._state.dsn = uri

        self._update_workload(event)

    def _ready(self):
        container = self.unit.get_container(WORKLOAD_CONTAINER)

        if container.can_connect():
            plan = container.get_plan()
            if plan.services.get(JIMM_SERVICE_NAME) is None:
                logger.warning("waiting for service")
                if self.unit.status.message == "":
                    self.unit.status = WaitingStatus("waiting for service")
                return False

            env_vars = plan.services.get(JIMM_SERVICE_NAME).environment

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
        egress_subnets = self._egress_subnets(self.model.get_binding(relation))
        self.vault.request_credentials(relation, egress_subnets, self.get_vault_nonce())

    def _on_vault_ready(self, event: vault_kv.VaultKvReadyEvent) -> None:
        self._update_workload(event)

    def _on_vault_gone_away(self, event: vault_kv.VaultKvGoneAwayEvent) -> None:
        self._update_workload(event)

    @requires_state_setter
    def _on_openfga_store_created(self, event: OpenFGAStoreCreateEvent) -> None:
        if not event.store_id:
            return

        info = self.openfga.get_store_info()
        if not info:
            logger.warning("openfga info not ready yet")
            return

        self._state.openfga_store_id = info.store_id
        self._state.openfga_token = info.token
        o = urlparse(info.http_api_url)
        self._state.openfga_address = o.hostname
        self._state.openfga_port = o.port
        self._state.openfga_scheme = o.scheme

        self._update_workload(event)

    @requires_state
    def _get_dns_name(self, event) -> str:
        default_dns_name = ""
        dns_name = self.config.get("dns-name", default_dns_name)
        if self._state.dns_name:
            dns_name = self._state.dns_name

        return dns_name

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
        self._state.dns_name = event.url

        self._update_workload(event)

    @requires_state_setter
    def _on_ingress_revoked(self, event: IngressPerAppRevokedEvent) -> None:
        del self._state.dns_name

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
            model = jimm_container.pull(model_path).read()
        except pebble.PathError:
            logger.warning("auth model not found at %s", model_path)
            raise LookupError("Failed to find auth model in JIMM's OCI image")

        if not model:
            raise ValueError("empty auth model found")

        model_hash = hashlib.new("md5")
        model_hash.update(model.encode())
        digest = model_hash.hexdigest()

        if digest == self._state.openfga_auth_model_hash:
            logger.info("auth model already exists, won't recreate")
            return

        model_json = json.loads(model)

        openfga_store_id = self._state.openfga_store_id
        openfga_token = self._state.openfga_token
        openfga_address = self._state.openfga_address
        openfga_port = self._state.openfga_port
        openfga_scheme = self._state.openfga_scheme

        if not openfga_address or not openfga_port or not openfga_scheme or not openfga_token or not openfga_store_id:
            logger.info("openfga is not ready yet, skipping auth model creation")
            return

        url = "{}://{}:{}/stores/{}/authorization-models".format(
            openfga_scheme,
            openfga_address,
            openfga_port,
            openfga_store_id,
        )
        headers = {"Content-Type": "application/json"}
        if openfga_token:
            headers["Authorization"] = "Bearer {}".format(openfga_token)

        # do the post request
        logger.info("posting to {}, with headers {}".format(url, headers))
        response = requests.post(
            url,
            json=model_json,
            headers=headers,
            verify=False,
        )
        if not response.ok:
            logger.error("failed to create authorisation model - %s", response.text)
            raise ValueError("failed to create authorisation model")
        data = response.json()
        authorization_model_id = data.get("authorization_model_id", "")
        if not authorization_model_id:
            logger.error("response does not contain authorization model id - %s", response.text)
            raise ValueError("response does not contain authorization model id")
        self._state.openfga_auth_model_id = authorization_model_id
        self._state.openfga_auth_model_hash = digest

    @property
    def _oauth_client_config(self) -> ClientConfig:
        dns = self.config.get("dns-name")
        if dns is None or dns == "":
            dns = "http://localhost"
        dns = ensureFQDN(dns)
        return ClientConfig(
            redirect_uri=urljoin(dns, "/auth/callback"),
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

        logger.info(
            "Pulling trusted ca certificates from %s relation.",
            self.trusted_cert_transfer.relationship_name,
        )
        for relation in self.model.relations.get(self.trusted_cert_transfer.relationship_name, []):
            # For some reason, relation.units includes our unit and app. Need to exclude them.
            for unit in set(relation.units).difference([self.app, self.unit]):
                # Note: this nested loop handles the case of multi-unit CA, each unit providing
                # a different ca cert, but that is not currently supported by the lib itself.
                cert_path = TRUSTED_CA_TEMPLATE.substitute(rel_id=relation.id)
                if cert := relation.data[unit].get("ca"):
                    container.push(cert_path, cert, make_dirs=True)

        stdout, stderr = container.exec(["update-ca-certificates", "--fresh"]).wait_output()
        logger.info("stdout update-ca-certificates: %s", stdout)
        logger.info("stderr update-ca-certificates: %s", stderr)

        return True

    def _on_trusted_certificate_available(self, event) -> None:
        self._update_workload(event)

    def _on_trusted_certificate_removed(self, event: CertificateRemovedEvent) -> None:
        # All certificates received from the relation are in separate files marked by the relation id.
        container = self.unit.get_container(WORKLOAD_CONTAINER)
        if not container.can_connect():
            event.defer()
            return
        cert_path = TRUSTED_CA_TEMPLATE.substitute(rel_id=event.relation_id)
        container.remove_path(cert_path, recursive=True)
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


def new_session_key():
    """Generate a session secret dict which holds a key value pair used for securing session tokens."""
    return {SESSION_KEY_LOOKUP: b64encode(os.urandom(64)).decode("utf-8")}


def ensureFQDN(dns: str) -> str:  # noqa: N802
    """Ensures a domain name has an https:// prefix."""
    if not dns.startswith("http"):
        dns = "https://" + dns
    return dns


if __name__ == "__main__":
    main(JimmOperatorCharm)
