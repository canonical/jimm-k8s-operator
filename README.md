# JIMM (K8s Charm)

[![CharmHub Badge](https://charmhub.io/juju-jimm-k8s/badge.svg)](https://charmhub.io/juju-jimm-k8s)
[![Release](https://github.com/canonical/jimm-k8s-operator/actions/workflows/publish.yaml/badge.svg)](https://github.com/canonical/jimm-k8s-operator/actions/workflows/publish.yaml)
[![Tests](https://github.com/canonical/jimm-k8s-operator/actions/workflows/test.yaml/badge.svg)](https://github.com/canonical/jimm-k8s-operator/actions/workflows/test.yaml)

## Description

JIMM is a extension of Juju, an open source orchestration engine, providing additional capabilities to your Juju environments.
Visit [our documentation](https://canonical-jaas-documentation.readthedocs-hosted.com/en/latest/) to gain a deeper understanding of what JIMM provides.

The JIMM K8s charm is the easiest and the recommended way to deploy JIMM. This charm installs and configures the JIMM server.

JIMM provides a number of useful features on top of Juju including,
- A single location to manage your Juju infrastructure.
- The ability to query across multiple Juju controllers simultaneously.
- Expanded authentication and authorisation functionality utilising OAuth2.0 and Relationship-based Access Control (ReBAC).

For users who want to deploy JIMM in its entirety (including its dependencies), it is recommended to start with [our tutorials](https://canonical-jaas-documentation.readthedocs-hosted.com/en/latest/tutorial) to get acquianted.

## Usage

JIMM can be deployed with the following command which will alias the deployed application name as simply `jimm`.

```
juju deploy juju-jimm-k8s jimm
```

## Documentation

For more detailed instructions on deploying and using JIMM, please visit our [documentation page](https://canonical-jaas-documentation.readthedocs-hosted.com/en/latest/).

## Contributing

Please see the [Juju SDK documentation](https://juju.is/docs/sdk) for more information about developing and improving charms. For developer guidance please check our contribution [guideline](CONTRIBUTING.md).
