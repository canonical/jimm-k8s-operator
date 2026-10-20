# Copyright 2025 Canonical Ltd
# See LICENSE file for licensing details.

import asyncio
import json
import logging
from pathlib import Path

import requests
import yaml
from oauth_tools import ExternalIdpService, deploy_identity_bundle
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = "juju-jimm-k8s"
HTTP_INGRESS_APP_NAME = "traefik"
HTTP_INGRESS_SERVICE_NAME = "traefik-lb"
JIMM_REQUEST_KWARGS = {"timeout": 30}


def get_jimm(jimm_address: str, url_path: str, **kwargs) -> requests.Response:
    """Query the externally exposed JIMM endpoint."""
    request_kwargs = {**JIMM_REQUEST_KWARGS, **kwargs}
    if jimm_address.startswith("https://"):
        request_kwargs.setdefault("verify", False)
    return requests.get(f"{jimm_address.rstrip('/')}{url_path}", **request_kwargs)


async def get_unit_data(ops_test: OpsTest, unit_name: str) -> dict:
    _, stdout, _ = await ops_test.juju("show-unit", unit_name)
    cmd_output = yaml.safe_load(stdout)
    return cmd_output[unit_name]


async def get_app_config(ops_test: OpsTest, app_name: str) -> dict:
    _, stdout, _ = await ops_test.juju("config", app_name, "--format=yaml")
    return yaml.safe_load(stdout)


async def get_jimm_address(ops_test: OpsTest) -> str:
    """Return the external HTTP URL for JIMM."""
    data = await get_unit_data(ops_test, f"{APP_NAME}/0")
    ingress_relation = next(
        (integration for integration in data["relation-info"] if integration["endpoint"] == "ingress"),
        None,
    )
    if not ingress_relation:
        raise RuntimeError("JIMM ingress relation is not present")

    ingress_data = ingress_relation.get("application-data", {}).get("ingress")
    if ingress_data:
        return json.loads(ingress_data)["url"].rstrip("/")

    jimm_address = await get_traefik_address(ops_test, HTTP_INGRESS_APP_NAME, HTTP_INGRESS_SERVICE_NAME)
    return jimm_address.rstrip("/")


async def wait_for_jimm_address(ops_test: OpsTest, timeout: int = 300) -> str:
    """Wait until Traefik publishes a reachable JIMM HTTP URL."""
    last_error: Exception | None = None
    attempts = max(1, timeout // 5)

    for _ in range(attempts):
        try:
            jimm_address = await get_jimm_address(ops_test)
            response = get_jimm(jimm_address, "/macaroons/publickey")
            if response.status_code == 200:
                return jimm_address
            last_error = RuntimeError(f"unexpected status from JIMM smoke check: {response.status_code}")
        except (requests.RequestException, RuntimeError, KeyError, json.JSONDecodeError) as exc:
            last_error = exc
        await asyncio.sleep(5)

    raise RuntimeError("timed out waiting for JIMM Traefik ingress") from last_error


async def get_service_external_ip(ops_test: OpsTest, service_name: str) -> str:
    """Return the external IP assigned to a service in the current model namespace."""
    namespace = ops_test.model_name
    if namespace is None:
        raise RuntimeError("ops_test.model_name is not available")

    _, stdout, _ = await ops_test.run(
        "kubectl",
        "get",
        "svc",
        "-n",
        namespace,
        service_name,
        "-o",
        "jsonpath={.status.loadBalancer.ingress[0].ip}",
    )
    external_ip = stdout.strip()
    if not external_ip:
        raise RuntimeError(f"service {service_name} does not have an external IP")
    return external_ip


async def wait_for_service_external_ip(ops_test: OpsTest, service_name: str, timeout: int = 300) -> str:
    """Wait until a service in the current model namespace has an external IP."""
    last_error: Exception | None = None
    attempts = max(1, timeout // 5)

    for _ in range(attempts):
        try:
            return await get_service_external_ip(ops_test, service_name)
        except RuntimeError as exc:
            last_error = exc
        await asyncio.sleep(5)

    raise RuntimeError(f"timed out waiting for service {service_name} external IP") from last_error


async def get_traefik_address(
    ops_test: OpsTest,
    traefik_app_name: str,
    service_name: str,
    app_name: str = APP_NAME,
) -> str:
    """Build the expected Traefik ingress URL for an application."""
    if ops_test.model_name is None:
        raise RuntimeError("ops_test.model_name is not available")

    config = await get_app_config(ops_test, traefik_app_name)
    settings = config.get("settings", {})
    routing_mode = settings.get("routing_mode", {}).get("value")
    external_hostname = settings.get("external_hostname", {}).get("value")
    external_ip = await get_service_external_ip(ops_test, service_name)

    if routing_mode == "subdomain":
        if not external_hostname:
            external_hostname = f"{external_ip}.sslip.io"
        return f"https://{ops_test.model_name}-{app_name}.{external_hostname}"

    return f"https://{external_ip}/{ops_test.model_name}-{app_name}"


async def deploy_jimm(
    ops_test: OpsTest,
    charm: Path,
    hydra_app_name: str,
    self_signed_certificates_app_name: str,
    ext_idp_service: ExternalIdpService,
) -> None:
    """(Optionally) Build and then deploy JIMM and all dependencies.

    Args:
        ops_test (OpsTest): Fixture for testing operator charms
        charm (Path): Path to prebuilt charm
    """
    # Build and deploy charm from local source folder
    # (Optionally build) and deploy charm from local source folder
    jimm_image_path = METADATA["resources"]["jimm-image"]["upstream-source"]
    resources = {"jimm-image": jimm_image_path}

    # Deploy the identity bundle first because it checks everything is in an active state and if we deploy JIMM apps
    # at the same time, then that check will fail.
    logger.info("deploying identity bundle")
    bundle_path = Path(__file__).parent / "identity-bundle.yaml"
    await deploy_identity_bundle(ops_test=ops_test, bundle_url=str(bundle_path), ext_idp_service=ext_idp_service)

    logger.info("configuring identity bundle ingress hostnames")
    admin_external_ip, public_external_ip = await asyncio.gather(
        wait_for_service_external_ip(ops_test, "traefik-admin-lb"),
        wait_for_service_external_ip(ops_test, "traefik-public-lb"),
    )
    await asyncio.gather(
        ops_test.juju("config", "traefik-admin", f"external_hostname={admin_external_ip}.sslip.io"),
        ops_test.juju("config", "traefik-public", f"external_hostname={public_external_ip}.sslip.io"),
    )

    # Deploy the charm and wait for active/idle status
    logger.info("deploying charms")
    async with ops_test.fast_forward():
        await asyncio.gather(
            ops_test.model.deploy(
                charm,
                resources=resources,
                application_name=APP_NAME,
                config={
                    "uuid": "f4dec11e-e2b6-40bb-871a-cc38e958af49",
                    "dns-name": "",
                    "public-key": "izcYsQy3TePp6bLjqOo3IRPFvkQd2IKtyODGqC6SdFk=",
                    "private-key": "ly/dzsI9Nt/4JxUILQeAX79qZ4mygDiuYGqc2ZEiDEc=",
                    "postgres-secret-storage": True,
                    "secure-session-cookies": True,
                    "juju-dashboard-location": "http://localhost/debug/info",
                },
                num_units=1,
            ),
            ops_test.model.deploy(
                "postgresql-k8s",
                application_name="jimm-db",
                channel="14/stable",
            ),
            ops_test.model.deploy(
                "self-signed-certificates",
                application_name="postgresql-certificates",
                channel="1/stable",
            ),
            ops_test.model.deploy(
                "openfga-k8s",
                application_name="openfga",
                channel="latest/stable",
            ),
            ops_test.model.deploy(
                "traefik-k8s",
                application_name="traefik",
                channel="latest/stable",
            ),
        )

    logger.info("enabling postgresql TLS with a separate certificate provider")
    await ops_test.model.integrate("jimm-db:certificates", "postgresql-certificates:certificates")

    logger.info("waiting for postgresql")
    await ops_test.model.wait_for_idle(["jimm-db"], raise_on_blocked=False, status="active", timeout=2000)

    logger.info("adding custom ca cert relation")
    await ops_test.model.integrate("{}:receive-ca-cert".format(APP_NAME), self_signed_certificates_app_name)

    logger.info("adding openfga postgresql relation")
    await ops_test.model.integrate("openfga:database", "jimm-db:database")

    logger.info("adding openfga relation")
    await ops_test.model.integrate(f"{APP_NAME}:openfga", "openfga")

    logger.info("adding postgresql relation")
    await ops_test.model.integrate(APP_NAME, "jimm-db:database")

    logger.info("adding oauth relation")
    await ops_test.model.integrate(f"{APP_NAME}:oauth", hydra_app_name)

    logger.info("adding traefik certificates relation")
    await ops_test.model.integrate(
        f"{HTTP_INGRESS_APP_NAME}:certificates",
        f"{self_signed_certificates_app_name}:certificates",
    )

    logger.info("configuring dedicated traefik http ingress")
    traefik_external_ip = await wait_for_service_external_ip(ops_test, HTTP_INGRESS_SERVICE_NAME)
    await ops_test.model.applications[HTTP_INGRESS_APP_NAME].set_config(
        {
            "routing_mode": "subdomain",
            "external_hostname": f"{traefik_external_ip}.sslip.io",
        }
    )

    logger.info("adding traefik http relation")
    await ops_test.model.integrate(f"{APP_NAME}:ingress", HTTP_INGRESS_APP_NAME)

    logger.info("adding traefik ssh relation")
    await ops_test.model.integrate(f"{APP_NAME}:ingress-ssh", HTTP_INGRESS_APP_NAME)

    await ops_test.model.wait_for_idle(timeout=2000)

    expected_jimm_address = await get_traefik_address(
        ops_test,
        HTTP_INGRESS_APP_NAME,
        HTTP_INGRESS_SERVICE_NAME,
    )
    logger.info("setting JIMM public URL to %s", expected_jimm_address)
    await ops_test.juju(
        "config",
        APP_NAME,
        f"dns-name={expected_jimm_address}",
        f"juju-dashboard-location={expected_jimm_address}/debug/info",
    )

    await ops_test.model.wait_for_idle(timeout=2000)
    jimm_address = await wait_for_jimm_address(ops_test)
    macaroon_publickey = get_jimm(jimm_address, "/macaroons/publickey")
    assert macaroon_publickey.status_code == 200
