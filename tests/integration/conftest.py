import glob

import pytest
from pytest_operator.plugin import OpsTest


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
