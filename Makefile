# Copyright 2024 Canonical Ltd.
CHARM_FILE := $(shell ls juju-jimm*.charm)

build:
	charmcraft pack

deploy:
	juju deploy ./$(CHARM_FILE) --resource jimm-image=localhost:32000/jimm:latest
