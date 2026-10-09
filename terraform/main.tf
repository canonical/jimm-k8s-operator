### Applications ###
resource "juju_application" "jimm" {
  name  = var.name
  trust = var.trust
  units = var.units

  charm {
    name     = var.jimm_charm.name
    channel  = var.jimm_charm.channel
    base     = var.jimm_charm.base
    revision = var.jimm_charm.revision
  }

  config = {
    uuid                               = var.jimm_config.uuid == "" ? random_uuid.jimm-uuid[0].result : var.jimm_config.uuid
    controller-admins                  = var.jimm_config.controller_admins
    log-level                          = var.jimm_config.log_level
    dns-name                           = var.jimm_config.dns_name
    postgres-secret-storage            = var.jimm_config.postgres-secret-storage
    public-key                         = var.jimm_config.public_key
    private-key                        = sensitive(var.jimm_config.private_key)
    oauth-group-claim-key              = var.jimm_config.oauth-group-claim-key
    idp-group-fetcher-type             = var.jimm_config.idp-group-fetcher-type
    idp-hook-service-address           = var.jimm_config.idp-hook-service-address
    audit-log-retention-period-in-days = var.jimm_config.audit-log-retention-period-in-days
    cors-allowed-origins               = var.jimm_config.cors-allowed-origins
    juju-dashboard-location            = var.jimm_config.juju-dashboard-location
    jwt-expiry                         = var.jimm_config.jwt-expiry
    macaroon-expiry-duration           = var.jimm_config.macaroon-expiry-duration
    secure-session-cookies             = var.jimm_config.secure-session-cookies
    session-cookie-max-age             = var.jimm_config.session-cookie-max-age
    oauth-client-credential-scopes     = var.jimm_config.oauth-client-credential-scopes
    oauth-optional-scopes              = var.jimm_config.oauth-optional-scopes
    session-expiry-duration            = var.jimm_config.session-expiry-duration
    ssh-port                           = var.jimm_config.ssh-port
    ssh-max-concurrent-connections     = var.jimm_config.ssh-max-concurrent-connections
    ssh-host-key-secret-id             = var.jimm_config.ssh-host-key-secret-id
  }

  model_uuid = var.model_uuid
}

### Misc ###

resource "random_uuid" "jimm-uuid" {
  count = var.jimm_config.uuid == "" ? 1 : 0
}


resource "juju_application" "grafana_agent" {
  count = var.deploy_grafana_agent ? 1 : 0

  name = "grafana-agent"

  charm {
    name     = var.grafana_agent_charm.name
    channel  = var.grafana_agent_charm.channel
    base     = var.grafana_agent_charm.base
    revision = var.grafana_agent_charm.revision
  }
  model_uuid = var.model_uuid
}
