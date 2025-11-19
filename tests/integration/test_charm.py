#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd
# See LICENSE file for licensing details.

import logging
import socket
from pathlib import Path
from typing import Optional

import pytest
import requests
from oauth_tools import (
    ExternalIdpService,
    access_application_login_page,
    complete_auth_code_login,
    get_cookie_from_browser_by_name,
    verify_page_loads,
)
from playwright.async_api import BrowserContext, Page
from pytest_operator.plugin import OpsTest
from utils import deploy_jimm

from tests.integration.utils import JIMM_ADDRESS

pytest_plugins = ["oauth_tools.fixtures"]
logger = logging.getLogger(__name__)


@pytest.mark.skip_if_deployed
@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    charm: Path,
    hydra_app_name: str,
    self_signed_certificates_app_name: str,
    ext_idp_service: ExternalIdpService,
) -> None:
    """Build the charm-under-test and deploy it together with related charms."""
    # Build and deploy charm from local source folder
    # (Optionally build) and deploy charm from local source folder

    await deploy_jimm(ops_test, charm, hydra_app_name, self_signed_certificates_app_name, ext_idp_service)


@pytest.mark.skip("Failing due to a new breaking resource in the login UI charm")
async def test_jimm_oauth_browser_login(
    ops_test: OpsTest,
    charm,
    page: Page,
    context: BrowserContext,
    user_email: str,
    ext_idp_service: ExternalIdpService,
):
    """Run a playwright test to perform the browser login flow and confirm the session cookie is valid."""

    logger.info("running browser flow login test")

    await access_application_login_page(page=page, url=f"{JIMM_ADDRESS}/auth/login")
    logger.info("completing external idp login")
    await complete_auth_code_login(page=page, ops_test=ops_test, ext_idp_service=ext_idp_service)
    redirect_url = f"{JIMM_ADDRESS}/debug/info"
    logger.info(f"verifying return to JIMM - expecting a final redirect to {redirect_url}")
    await verify_page_loads(page=page, url=redirect_url)

    logger.info("verifying session cookie")
    # Verifying that the login flow was successful is application specific.
    # The test uses JIMM's /auth/whoami endpoint to verify the session cookie is valid
    jimm_session_cookie = await get_cookie_from_browser_by_name(browser_context=context, name="jimm-browser-session")
    request = requests.get(
        f"{JIMM_ADDRESS}/auth/whoami",
        headers={"Cookie": f"jimm-browser-session={jimm_session_cookie}"},
        verify=False,
    )
    assert request.status_code == 200
    assert request.json()["email"] == user_email

    # check ssh server is opened.
    # TODO(simonedutto): once the juju implementation is working, we should test it properly.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(("10.64.140.43", 17022))
    assert result == 0


async def test_openfga_integration(openfga_integration_data: Optional[dict]) -> None:
    assert openfga_integration_data, "Openfga integration data is empty."

    assert openfga_integration_data["store_id"]
    assert openfga_integration_data["grpc_api_url"]
    assert openfga_integration_data["http_api_url"]
    assert openfga_integration_data["token_secret_id"]
