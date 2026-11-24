# AGENTS.md

## Start here

- [README.md](./README.md) — project overview, requirements, and build instructions.
- [CONTRIBUTING.md](./CONTRIBUTING.md) — contribution workflow for code and docs.

## Things to keep in mind

- The K8s charm is the way the Jimm server is deployed.
- This charm is mainly consumed from a Terraform plan similar to the one we have in `./terraform`.
- The integration tests deploy most things within the same model, but it's also common to consume all dependencies via Juju offers.
- Consider every charm change in both new and existing deployments. If a new feature complicates an in-place upgrade, test the upgrade. If the test is difficult to automate, document how to run it manually.
- If deploying a previous revision does not easily revert a new feature, explicitly document the rollback limitations.
- Add new Python dependencies from PyPI to [`requirements.txt`](./requirements.txt). Existing vendored charm libraries are checked in under [`lib/charms/`](./lib/charms/); no separate fetch step is needed to build or test the charm.
