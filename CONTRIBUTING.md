# Contributing

## Overview

This documents explains the processes and practices recommended for contributing enhancements to
this operator.

- If you would like to chat with us about your use-cases, you can reach
  us at [Discourse](https://chat.charmhub.io/charmhub/channels/jaas).
- Familiarising yourself with the [Charmed Operator Framework](https://juju.is/docs/sdk) library
  will help you a lot when working on new features or bug fixes.
- All enhancements require review before being merged. Code review typically examines
  - code quality
  - test coverage
  - user experience for Juju administrators this charm.
- Please help us out in ensuring easy to review branches by rebasing your pull request branch onto
  the `main` branch. This also avoids merge commits and creates a linear Git commit history.

## Developing

You can create an environment for development with `tox`:

```shell
virtualenv -p python3 venv
source venv/bin/activate
pip install -r requirements-dev.txt
pip install tox
```

The charm additionally requires the following relations:
- ingress, interface: ingress
- database, interface: postgresql_client
- vault, interface: vault-kv
- openfga, interface: openfga
- certificates, interface: tls-certificates

### Testing

```shell
tox -e fmt           # update your code according to linting rules
tox -e lint          # code style
tox -e unit          # unit tests
tox -e integration   # integration tests
tox                  # runs 'lint' and 'unit' environments
```


## Build charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

### Deploy

```bash
# Create a model
juju add-model dev
# Enable DEBUG logging
juju model-config logging-config="<root>=INFO;unit=DEBUG"
# Deploy the charm
juju deploy ./juju-jimm-k8s_ubuntu-22.04-amd64.charm
```

### Integration tests
Integration tests require the following setup:
1. A microk8s cluster - `sudo snap install microk8s`
2. Enable add-ons - `sudo microk8s enable ingress hostpath-storage dns registry`
3. Ensure rbac is disabled - `sudo microk8s disable rbac`
4. Enable load-balancer add-on `sudo microk8s enable metallb`. Supply a CIDR like `10.64.140.0/24`
5. A Juju controller on microk8s `juju bootstrap microk8s`
6. `kubectl` must be installed - `sudo snap install kubectl`
7. Your kubectl must be configured to talk to microk8s - `microk8s config > ~/.kube/config`
8. Setup the ability for Microk8s to pull from a private ghcr (Github Container Registry):
   1. Obtain a Github PAT token that has at least `read:packages` access and can access `github.com/canonical/jimm`.
   2. Run the following commands (adding values for the username/password placeholders):

          read -r -d '' REGISTRY_CONFIG << EOL || true
          [plugins."io.containerd.grpc.v1.cri".registry.configs."ghcr.io".auth]
              username = "<your-username-here>"
              password = "<your-PAT-token-here>"
          EOL
                    
          echo "$REGISTRY_CONFIG" | sudo tee -a /var/snap/microk8s/current/args/containerd-template.toml

          sudo snap restart microk8s.daemon-containerd

9.  Create the `venv` and install `tox` as described above.
10. Run the test (optionally keep the model for debugging) - `tox -e integration -- --keep-models`