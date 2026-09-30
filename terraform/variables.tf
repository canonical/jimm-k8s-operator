variable "model_uuid" {
  type    = string
  default = "jimm"
}

variable "name" {
  description = "JIMM application name"
  type        = string
  default     = "jimm"
}

variable "trust" {
  description = "The status to grant the JIMM application full access to the cluster."
  type        = bool
  default     = true
}

variable "jimm_charm" {
  description = "The JIMM application charm operator information."
  type = object({
    name : string
    channel : string
    base : string
    revision : number
  })
  default = {
    name     = "juju-jimm-k8s"
    channel  = "3/stable"
    base     = "ubuntu@22.04"
    revision = 0
  }
}

// The JIMM charm configuration
// More info at https://charmhub.io/juju-jimm-k8s/configurations
variable "jimm_config" {
  type = object({
    uuid                               = optional(string, "")
    controller_admins                  = optional(string, "")
    log_level                          = optional(string, "info")
    dns_name                           = optional(string, "")
    public_key                         = optional(string, "")
    private_key                        = optional(string, "")
    oauth-group-claim-key              = optional(string, "")
    postgres-secret-storage            = optional(bool, false)
    audit-log-retention-period-in-days = optional(string, "0")
    cors-allowed-origins               = optional(string, "")
    juju-dashboard-location            = optional(string, "https://jaas.ai/models")
    jwt-expiry                         = optional(string, "5m")
    macaroon-expiry-duration           = optional(string, "24h")
    secure-session-cookies             = optional(bool, true)
    session-cookie-max-age             = optional(number, 86400)
    oauth-client-credential-scopes     = optional(string, "")
    oauth-optional-scopes              = optional(string, "")
    session-expiry-duration            = optional(string, "6h")
    ssh-port                           = optional(number, 17022)
    ssh-max-concurrent-connections     = optional(number, 100)
    ssh-host-key-secret-id             = optional(string, "")
  })
  description = <<EOT
    jimm_config = {
      uuid: "The UUID advertised by the JIMM controller. If not provided, one will be generated for you."
      controller_admins: "Whitespace separated list of candid users (or groups) that are made controller admins by default."
      log_level: "Level to out log messages at, one of debug, info, warn, error, dpanic, panic, and fatal."
      dns_name: "A fallback for JIMM's address if the ingress integration does not provide it."
      # you can generate this keypair using `go run github.com/go-macaroon-bakery/macaroon-bakery/cmd/bakery-keygen/v3@latest
      public_key: "The public part of JIMM's macaroon bakery keypair."
      private_key: "The private part of JIMM's macaroon bakery keypair."
      oauth-group-claim-key: "The key in the JWT where the group claim is located."
      postgres-secret-storage: "Whether to use PostgreSQL for secret storage instead of Vault."
      audit-log-retention-period-in-days: "How long to hold audit logs for in days, i.e., 10 = 10 days. If 0 is set, the logs will never be purged. Logs are purged at 9AM UTC. Defaults to 0."
      cors-allowed-origins: "Space separated list of addresses which are allowed to make requests cross-origin."
      juju-dashboard-location: "URL of the Juju Dashboard for this controller."
      jwt-expiry: "Duration for the JWT expiry (defaults to 5 minutes). This is the JWT JIMM sends to a Juju controller to authenticate model related commands. Increase this if long running websocket connections are failing due to authentication errors."
      macaroon-expiry-duration: "Expiry duration for authentication macaroons."
      secure-session-cookies: "Whether HTTPS must be enabled to set session cookies."
      session-cookie-max-age: "The max age for the session cookies in seconds, on subsequent logins, the session instance extended by this amount."
      oauth-client-credential-scopes: "Space separated OAuth scopes requested only for the client credentials flow. Specifying additional scopes here will require that service accounts used to authenticate to JIMM will require these additional scopes at creation time."
      oauth-optional-scopes: "Space separated extra OAuth scopes to request and forward, in addition to JIMM's default OAuth scope request. These scopes are only applied to the authorisation code and device code flows. This is useful for requesting scopes that the identity provider supports but may omit from advertised metadata, such as a group claim scope."
      session-expiry-duration: "Expiry duration for JIMM session tokens. These tokens are used by clients and their expiry determines how frequently a user must login."
      ssh-port: "The port that JIMM will expose the jump server on."
      ssh-max-concurrent-connections: "The maximum number of concurrent SSH connections allowed."
      ssh-host-key-secret-id: "The secret ID of the SSH host key."
    }
  EOT
}

variable "units" {
  description = "Number of JIMM units. Default to 3 for HA."
  type        = number
  default     = 3 #
}

variable "deploy_grafana_agent" {
  description = "Whether to deploy the Grafana Agent application alongside JIMM."
  type        = bool
  default     = false
}

variable "grafana_agent_charm" {
  description = "The grafana agent application charm operator information."
  type = object({
    name : string
    channel : string
    base : string
    revision : number
  })
  default = {
    name     = "grafana-agent-k8s"
    channel  = "latest/stable"
    base     = "ubuntu@22.04"
    revision = 0
  }
}

variable "oauth" {
  description = "OAuth integration configuration. Provide either offer_url or application_name."
  type = object({
    offer_url        = optional(string)
    application_name = optional(string)
  })
  default = {}
}

variable "postgresql" {
  description = "PostgreSQL integration configuration. Provide either offer_url or application_name."
  type = object({
    offer_url        = optional(string)
    application_name = optional(string)
  })
  default = {}
}

variable "openfga" {
  description = "OpenFGA integration configuration. Provide either offer_url or application_name."
  type = object({
    offer_url        = optional(string)
    application_name = optional(string)
  })
  default = {}
}

variable "vault" {
  description = "Vault integration configuration. Provide either offer_url or application_name."
  type = object({
    offer_url        = optional(string)
    application_name = optional(string)
  })
  default = {}
}

variable "ingress" {
  description = "Ingress integration configuration. Provide either offer_url or application_name."
  type = object({
    offer_url        = optional(string)
    application_name = optional(string)
  })
  default = {}
}

variable "metrics_endpoint_offer_url" {
  description = "Grafana Metrics Endpoint Offer URL"
  type        = string
  default     = null
}

variable "logging_consumer_offer_url" {
  description = "Grafana Agent Logging Offer URL"
  type        = string
  default     = null
}

variable "grafana_dashboard_consumer_offer_url" {
  description = "Grafana Agent Dashboard Offer URL"
  type        = string
  default     = null
}
