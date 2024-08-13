#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd
# See LICENSE file for licensing details.

import logging
import os

import pytest
import requests
from oauth_tools import (
    ExternalIdpService,
    access_application_login_page,
    complete_auth_code_login,
    get_cookie_from_browser_by_name,
    verify_page_loads,
)
from playwright.async_api._generated import BrowserContext, Page
from pytest_operator.plugin import OpsTest
from utils import deploy_jimm

pytest_plugins = ["oauth_tools.fixtures"]
logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_jimm_oauth_browser_login(
    ops_test: OpsTest,
    charm,
    page: Page,
    context: BrowserContext,
    hydra_app_name: str,
    self_signed_certificates_app_name: str,
    user_email: str,
    ext_idp_service: ExternalIdpService,
):
    """Build the charm-under-test and deploy it together with related charms.

    Run a playwright test to perform the browser login flow and confirm the session cookie is valid.
    """
    # Build and deploy charm from local source folder
    # (Optionally build) and deploy charm from local source folder
    jimm_env = await deploy_jimm(ops_test, charm, hydra_app_name, self_signed_certificates_app_name, ext_idp_service)
    logger.info("running browser flow login test")
    logger.info(f"jimm's address is {jimm_env.jimm_address.geturl()}")
    jimm_login_page = os.path.join(jimm_env.jimm_address.geturl(), "auth/login")

    await access_application_login_page(page=page, url=jimm_login_page)
    logger.info("completing external idp login")
    await complete_auth_code_login(page=page, ops_test=ops_test, ext_idp_service=ext_idp_service)
    redirect_url = os.path.join(jimm_env.jimm_address.geturl(), "debug/info")
    logger.info(f"verifying return to JIMM - expecting a final redirect to {redirect_url}")
    await verify_page_loads(page=page, url=redirect_url)

    logger.info("verifying session cookie")
    # Verifying that the login flow was successful is application specific.
    # The test uses JIMM's /auth/whoami endpoint to verify the session cookie is valid
    jimm_session_cookie = await get_cookie_from_browser_by_name(browser_context=context, name="jimm-browser-session")
    request = requests.get(
        os.path.join(jimm_env.jimm_address.geturl(), "auth/whoami"),
        headers={"Cookie": f"jimm-browser-session={jimm_session_cookie}"},
        verify=False,
    )
    assert request.status_code == 200
    assert request.json()["email"] == user_email
