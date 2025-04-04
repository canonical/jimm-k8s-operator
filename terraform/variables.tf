variable "model" {
  type    = string
  default = "jimm"
}

variable "include_oauth-external-idp-integrator" {
  description = <<EOT
  If you set this to true, you need to configure the oauth-external-idp-integrator charm.
  In this way you can use the JIMM charm without the iam-bundle.
  EOT
  type        = bool
  default     = false
}

variable "name" {
  description = "JIMM application name"
  type        = string
  default     = "jimm"
}

variable "trust" {
  description = "The status to grant the Juju application full access to the cluster."
  type        = bool
  default     = true
}


variable "charm" {
  description = "The application charm operator information."
  type = object({
    name : string
    channel : string
    base : string
  })
  default = {
    name    = "juju-jimm-k8s"
    channel = "3/edge"
    base    = "ubuntu@22.04"
  }
}

// The JIMM charm configuration
// More info at https://charmhub.io/juju-jimm-k8s/configurations
variable "jimm_config" {
  type = object({
    uuid              = optional(string, "")
    controller_admins = optional(string, "")
    log_level         = optional(string, "info")
    dns_name          = string
    public_key        = optional(string, "eaj1OMeHsd8OyDTqE+OOpkmWCNd1Py6mF1i3UD+VoCk=") // DO NOT USE IN PRODUCTION
    private_key       = optional(string, "vx+aEalWSM524h9NAZcyZlUFvOLkiRN2J7K5uz9FW1c=") // DO NOT USE IN PRODUCTION
  })
  description = <<EOT
    jimm_config = {
      uuid: "The UUID advertised by the JIMM controller. If not provided, one will be generated for you."
      controller_admins: "Whitespace separated list of candid users (or groups) that are made controller admins by default."
      log_level: "Level to out log messages at, one of debug, info, warn, error, dpanic, panic, and fatal."
      dns_name: "DNS hostname that JIMM is being served from."
      public_key: "The public part of JIMM's macaroon bakery keypair."
      private_key: "The private part of JIMM's macaroon bakery keypair."
    }
  EOT
}

variable "units" {
  description = "Number of JIMM units. Default to 3 for HA."
  type        = number
  default     = 3 #
}

variable "oauth-external-idp-integrator_application_name" {
  description = "Oauth External Idp Integrator application name"
  type        = string
  default     = "idp-integrator"
}

variable "oauth-external-idp-integrator_charm_channel" {
  description = "Oauth External Idp Integrator charm channel"
  type        = string
  default     = "latest/edge"
}

variable "oauth-external-idp-integrator_charm_revision" {
  description = "Oauth External Idp Integrator charm revision"
  type        = number
  default     = 6
}

variable "oauth-external-idp-integrator_charm_base" {
  description = "Oauth External Idp Integrator charm base"
  type        = string
  default     = "ubuntu@22.04"
}

variable "oauth-external-idp-integrator_config" {
  type = object({
    issuer_url             = string
    authorization_endpoint = string
    introspection_endpoint = string
    jwks_endpoint          = string
    token_endpoint         = string
    userinfo_endpoint      = string
    scope                  = string
    client_id              = string
    client_secret          = string
  })
  description = <<EOT
    oauth-external-idp-integrator_config = {
      issuer_url: ""
      authorization_endpoint: ""
      introspection_endpoint: ""
      jwks_endpoint: ""
      token_endpoint: ""
      userinfo_endpoint: ""
      scope: ""
      client_id: ""
      client_secret: ""
    }
  EOT
  default = {
    # https://developers.google.com/identity/openid-connect/openid-connect#discovery
    issuer_url             = "https://accounts.google.com"
    authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    introspection_endpoint = "https://www.googleapis.com/oauth2/v1/tokeninfo"
    jwks_endpoint          = "https://www.googleapis.com/oauth2/v3/certs"
    token_endpoint         = "https://oauth2.googleapis.com/token"
    userinfo_endpoint      = "https://openidconnect.googleapis.com/v1/userinfo"
    scope                  = "openid profile email"
    client_id              = "your-client-id"
    client_secret          = "your-client-secret"
  }
}

variable "oauth_offer_url" {
  description = "OAuth Offer URL"
  type        = string
  default     = ""
}

variable "postgresql_offer_url" {
  description = "PostgreSQL Offer URL"
  type        = string
}

variable "openfga_offer_url" {
  description = "OpenFGA Offer URL"
  type        = string
}

variable "vault_offer_url" {
  description = "Vault Offer URL"
  type        = string
  default     = ""
}

variable "ingress_offer_url" {
  description = "Ingress Offer URL"
  type        = string
}
