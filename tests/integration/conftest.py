import functools
import glob
from typing import Callable, Optional

import pytest
import pytest_asyncio
import yaml
from pytest_operator.plugin import OpsTest

from tests.integration.utils import APP_NAME


def pytest_addoption(parser):
    parser.addoption("--localCharm", action="store_true", help="use local pre-built charm")


@pytest.fixture(scope="module")
async def charm(pytestconfig, ops_test: OpsTest):
    if pytestconfig.getoption("localCharm"):
        charm = glob.glob("./*.charm")
        if len(charm) != 1:
            raise ValueError(f"Found {len(charm)} file(s) with .charm extension.")
        return charm[0]
    else:
        charm = await ops_test.build_charm(".")
        return charm


async def get_unit_data(ops_test: OpsTest, unit_name: str) -> dict:
    show_unit_cmd = f"show-unit {unit_name}".split()
    _, stdout, _ = await ops_test.juju(*show_unit_cmd)
    cmd_output = yaml.safe_load(stdout)
    return cmd_output[unit_name]


async def get_integration_data(
    ops_test: OpsTest, app_name: str, integration_name: str, unit_num: int = 0
) -> Optional[dict]:
    data = await get_unit_data(ops_test, f"{app_name}/{unit_num}")
    return next(
        (integration for integration in data["relation-info"] if integration["endpoint"] == integration_name),
        None,
    )


async def get_app_integration_data(
    ops_test: OpsTest,
    app_name: str,
    integration_name: str,
    unit_num: int = 0,
) -> Optional[dict]:
    data = await get_integration_data(ops_test, app_name, integration_name, unit_num)
    return data["application-data"] if data else None


@pytest_asyncio.fixture
async def app_integration_data(ops_test: OpsTest) -> Callable:
    return functools.partial(get_app_integration_data, ops_test)


@pytest_asyncio.fixture
async def openfga_integration_data(app_integration_data: Callable) -> Optional[dict]:
    return await app_integration_data(APP_NAME, "openfga")
