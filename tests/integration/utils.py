import asyncio
import logging
import os
from pathlib import Path
from typing import Dict
from urllib.parse import ParseResult

import requests
import yaml
from juju.unit import Unit
from oauth_tools import ExternalIdpService, deploy_identity_bundle
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = "juju-jimm-k8s"


async def get_unit_by_name(unit_name: str, unit_index: str, unit_list: Dict[str, Unit]) -> Unit:
    return unit_list.get("{unitname}/{unitindex}".format(unitname=unit_name, unitindex=unit_index))


class JimmEnv:
    def __init__(self, jimm_address: ParseResult) -> None:
        self.jimm_address = jimm_address


async def deploy_jimm(
    ops_test: OpsTest,
    charm: Path,
    hydra_app_name: str,
    self_signed_certificates_app_name: str,
    ext_idp_service: ExternalIdpService,
) -> JimmEnv:
    """(Optionally) Build and then deploy JIMM and all dependencies.

    Args:
        ops_test (OpsTest): Fixture for testing operator charms
        charm (Path): Path to prebuilt charm

    Returns:
        JimmEnv: A class with member variables that are useful for test functions.
    """
    # Build and deploy charm from local source folder
    # (Optionally build) and deploy charm from local source folder
    jimm_image_path = METADATA["resources"]["jimm-image"]["upstream-source"]
    resources = {"jimm-image": jimm_image_path}
    jimm_address = ParseResult(scheme="http", netloc="test.jimm.localhost", path="", params="", query="", fragment="")

    # Deploy the identity bundle first because it checks everything is in an active state and if we deploy JIMM apps
    # at the same time, then that check will fail.
    logger.info("deploying identity bundle")
    await deploy_identity_bundle(ops_test=ops_test, bundle_channel="0.2/edge", ext_idp_service=ext_idp_service)

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
                    "dns-name": jimm_address.netloc,
                    "public-key": "izcYsQy3TePp6bLjqOo3IRPFvkQd2IKtyODGqC6SdFk=",
                    "private-key": "ly/dzsI9Nt/4JxUILQeAX79qZ4mygDiuYGqc2ZEiDEc=",
                    "postgres-secret-storage": True,
                    # This is used by JIMM as the final redirect URL after doing the browser auth flow.
                    # Since we don't deploy the dashboard for integration tests, we just set this parameter
                    # to one of HTTP endpoints of JIMM.
                    "juju-dashboard-location": os.path.join(jimm_address.geturl(), "debug/info"),
                },
            ),
            ops_test.model.deploy("nginx-ingress-integrator", application_name="jimm-ingress", channel="latest/stable"),
            ops_test.model.deploy(
                "postgresql-k8s",
                application_name="jimm-db",
                channel="14/stable",
            ),
            ops_test.model.deploy(
                "openfga-k8s",
                application_name="openfga",
                channel="2.0/stable",
            ),
        )

    logger.info("waiting for postgresql")
    await ops_test.model.wait_for_idle(
        apps=["jimm-db"],
        status="active",
        raise_on_blocked=True,
        timeout=2000,
    )

    logger.info("adding custom ca cert relation")
    await ops_test.model.integrate("{}:receive-ca-cert".format(APP_NAME), self_signed_certificates_app_name)

    logger.info("adding ingress relation")
    await ops_test.model.integrate("{}:nginx-route".format(APP_NAME), "jimm-ingress")

    logger.info("adding openfga postgresql relation")
    await ops_test.model.integrate("openfga:database", "jimm-db:database")

    logger.info("adding openfga relation")
    await ops_test.model.integrate(APP_NAME, "openfga")

    logger.info("adding postgresql relation")
    await ops_test.model.integrate(APP_NAME, "jimm-db:database")

    logger.info("adding oauth relation")
    await ops_test.model.integrate(f"{APP_NAME}:oauth", hydra_app_name)

    await ops_test.model.wait_for_idle(timeout=2000)
    jimm_debug_info = requests.get(os.path.join(jimm_address.geturl(), "debug/info"))
    assert jimm_debug_info.status_code == 200
    logger.info("jimm info = %s", jimm_debug_info.json())
    return JimmEnv(jimm_address)
