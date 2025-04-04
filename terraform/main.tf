### Applications ###
resource "juju_model" "jimm" {
  name = var.model
}

resource "juju_application" "jimm" {
  name  = var.name
  model = juju_model.jimm.name
  trust = var.trust
  units = var.units

  charm {
    name    = var.charm.name
    channel = var.charm.channel
    base    = var.charm.base
  }

  config = {
    uuid                    = var.jimm_config.uuid == "" ? random_uuid.jimm-uuid[0].result : var.jimm_config.uuid
    controller-admins       = var.jimm_config.controller_admins
    log-level               = var.jimm_config.log_level
    dns-name                = var.jimm_config.dns_name
    postgres-secret-storage = false
    public-key              = var.jimm_config.public_key
    private-key             = sensitive(var.jimm_config.private_key)
  }

}

resource "juju_application" "oauth-external-idp-integrator" {
  name  = var.oauth-external-idp-integrator_application_name
  count = var.include_oauth-external-idp-integrator ? 1 : 0
  model = juju_model.jimm.name
  trust = true

  charm {
    name     = "oauth-external-idp-integrator"
    channel  = var.oauth-external-idp-integrator_charm_channel
    revision = var.oauth-external-idp-integrator_charm_revision
    base     = var.oauth-external-idp-integrator_charm_base
  }

  config = {
    client_id              = var.oauth-external-idp-integrator_config.client_id
    client_secret          = sensitive(var.oauth-external-idp-integrator_config.client_secret)
    issuer_url             = var.oauth-external-idp-integrator_config.issuer_url
    authorization_endpoint = var.oauth-external-idp-integrator_config.authorization_endpoint
    introspection_endpoint = var.oauth-external-idp-integrator_config.introspection_endpoint
    jwks_endpoint          = var.oauth-external-idp-integrator_config.jwks_endpoint
    token_endpoint         = var.oauth-external-idp-integrator_config.token_endpoint
    userinfo_endpoint      = var.oauth-external-idp-integrator_config.userinfo_endpoint
    scope                  = var.oauth-external-idp-integrator_config.scope
  }

  units = 1
}

### Misc ###

resource "random_uuid" "jimm-uuid" {
  count = var.jimm_config.uuid == "" ? 1 : 0
}


