#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd
# See LICENSE file for licensing details.

import json
import logging
import re
import secrets
import socket
from pathlib import Path
from typing import Callable, Optional

import pytest
from oauth_tools import (
    ExternalIdpService,
    access_application_login_page,
    get_cookie_from_browser_by_name,
)
from playwright.async_api import BrowserContext, Page
from pytest_operator.plugin import OpsTest
from utils import (
    APP_NAME,
    deploy_jimm,
    get_jimm,
    get_jimm_address,
    get_service_external_ip,
)

pytest_plugins = ["oauth_tools.fixtures"]
logger = logging.getLogger(__name__)
LOCAL_TEST_USER_PASSWORD = "Password123"


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


async def test_certificate_transfer_integration(ops_test: OpsTest, app_integration_data: Callable) -> None:
    """Verify transferred CA certificates are written to JIMM's trust store."""
    relation_data = await app_integration_data(APP_NAME, "receive-ca-cert")
    assert relation_data is not None, "certificate-transfer relation is missing"

    certificates = json.loads(relation_data["certificates"])
    assert certificates, "certificate-transfer relation did not provide any certificates"
    assert all(certificate.startswith("-----BEGIN CERTIFICATE-----") for certificate in certificates)

    if ops_test.model_name is None:
        raise RuntimeError("ops_test.model_name is not available")
    _, ca_bundle, _ = await ops_test.run(
        "kubectl",
        "exec",
        "-n",
        ops_test.model_name,
        f"{APP_NAME}-0",
        "-c",
        "jimm",
        "--",
        "cat",
        "/usr/local/share/ca-certificates/trusted-ca-certs.crt",
    )

    for certificate in certificates:
        assert certificate.rstrip() in ca_bundle


async def test_jimm_oauth_browser_login(
    ops_test: OpsTest,
    charm,
    page: Page,
    context: BrowserContext,
):
    """Run a playwright test to perform the browser login flow and confirm the session cookie is valid."""

    jimm_address = await get_jimm_address(ops_test)
    local_user_email = f"test-{secrets.token_hex(4)}@example.com"

    logger.info("running browser flow login test")

    await access_application_login_page(page=page, url=f"{jimm_address}/auth/login")
    logger.info("registering a local identity user")
    await page.wait_for_url(re.compile(r"^https://[^/]+/ui/login.*$"))
    async with page.expect_navigation(wait_until="domcontentloaded"):
        await page.get_by_role("link", name="Register").click()
    await page.get_by_role("textbox").fill(local_user_email)
    await page.get_by_role("button", name="Sign up").click()
    await page.get_by_placeholder("Your password").nth(0).fill(LOCAL_TEST_USER_PASSWORD)
    await page.get_by_placeholder("Your password").nth(1).fill(LOCAL_TEST_USER_PASSWORD)
    async with page.expect_navigation(wait_until="domcontentloaded"):
        await page.get_by_role("button", name="Next").click()

    logger.info("logging into JIMM with the registered user")
    await access_application_login_page(page=page, url=f"{jimm_address}/auth/login")
    await page.wait_for_url(re.compile(r"^https://[^/]+/ui/login.*$"))
    await page.get_by_placeholder("Your Email").fill(local_user_email)
    async with page.expect_navigation(wait_until="domcontentloaded"):
        await page.get_by_role("button", name="Continue").click()
    await page.get_by_placeholder("Your Password").fill(LOCAL_TEST_USER_PASSWORD)
    async with page.expect_navigation(wait_until="domcontentloaded"):
        await page.get_by_role("button", name="Sign in").click()

    logger.info("waiting for browser flow to return to JIMM")
    await page.wait_for_url(re.compile(rf"^{re.escape(jimm_address)}/(?:auth/callback|debug/info)(?:[/?#].*)?$"))

    logger.info("verifying session cookie")
    applicable_cookies = await context.cookies([f"{jimm_address}/auth/whoami"])
    jimm_session_cookie = next(
        (cookie["value"] for cookie in applicable_cookies if cookie["name"] == "jimm-browser-session"),
        None,
    )
    if jimm_session_cookie is None:
        jimm_session_cookie = await get_cookie_from_browser_by_name(
            browser_context=context,
            name="jimm-browser-session",
        )
    assert jimm_session_cookie is not None
    request = get_jimm(
        jimm_address,
        "/auth/whoami",
        cookies={"jimm-browser-session": jimm_session_cookie},
    )
    assert request.status_code == 200
    assert request.json()["email"] == local_user_email
    assert page.url.startswith(f"{jimm_address}/debug/info")

    # check ssh server is opened.
    # TODO(simonedutto): once the juju implementation is working, we should test it properly.
    traefik_lb_ip = await get_service_external_ip(ops_test, "traefik-lb")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((traefik_lb_ip, 17022))
    assert result == 0


async def test_openfga_integration(openfga_integration_data: Optional[dict]) -> None:
    assert openfga_integration_data, "Openfga integration data is empty."

    assert openfga_integration_data["store_id"]
    assert openfga_integration_data["grpc_api_url"]
    assert openfga_integration_data["http_api_url"]
    assert openfga_integration_data["token_secret_id"]
