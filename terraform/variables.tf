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
    uuid              = optional(string, "")
    controller_admins = optional(string, "")
    log_level         = optional(string, "info")
    dns_name          = optional(string, "")
    public_key        = optional(string, "")
    private_key       = optional(string, "")
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

variable "tracing_consumer_offer_url" {
  description = "Grafana Agent Tracing Consumer Offer URL"
  type        = string
  default     = null
}
