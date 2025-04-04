### Integrations ###
# The reason why we have this data is to verify the offer exists for the offer variable
# set in the variables.

data "juju_offer" "database" {
  url = var.postgresql_offer_url
}

data "juju_offer" "ingress" {
  url = var.ingress_offer_url
}

data "juju_offer" "openfga" {
  url = var.openfga_offer_url
}

data "juju_offer" "vault" {
  url = var.vault_offer_url
}

data "juju_offer" "oauth" {
  url = var.oauth_offer_url
}

resource "juju_integration" "jimm_openfga" {
  model = juju_model.jimm.name

  application {
    name     = juju_application.jimm.name
    endpoint = "openfga"
  }

  application {
    offer_url = data.juju_offer.openfga.url
  }
}

resource "juju_integration" "jimm_vault" {
  model = juju_model.jimm.name

  application {
    name     = juju_application.jimm.name
    endpoint = "vault"
  }

  application {
    offer_url = data.juju_offer.vault.url
  }
}

resource "juju_integration" "jimm_postgresql" {
  model = juju_model.jimm.name

  application {
    name     = juju_application.jimm.name
    endpoint = "database"
  }

  application {
    offer_url = data.juju_offer.database.url
  }
}

resource "juju_integration" "jimm_oauth" {
  model = juju_model.jimm.name

  application {
    name = juju_application.jimm.name
  }

  application {
    offer_url = data.juju_offer.oauth.url
  }
}

resource "juju_integration" "jimm_ingress" {
  model = juju_model.jimm.name

  application {
    name     = juju_application.jimm.name
    endpoint = "ingress"
  }

  application {
    offer_url = data.juju_offer.ingress.url
  }
}

