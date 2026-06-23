# Add these integration resources
resource "juju_integration" "grafana_metrics_endpoint" {
  count = var.metrics_endpoint_offer_url != null ? 1 : 0

  application {
    name     = juju_application.grafana_agent[0].name
    endpoint = "metrics-endpoint"
  }

  application {
    offer_url = var.metrics_endpoint_offer_url
  }
  model_uuid = var.model_uuid
}

resource "juju_integration" "grafana_logging_consumer" {
  count = var.logging_consumer_offer_url != null ? 1 : 0

  application {
    name     = juju_application.grafana_agent[0].name
    endpoint = "logging-consumer"
  }

  application {
    offer_url = var.logging_consumer_offer_url
  }
  model_uuid = var.model_uuid
}

resource "juju_integration" "grafana_dashboard_consumer" {
  count = var.grafana_dashboard_consumer_offer_url != null ? 1 : 0

  application {
    name     = juju_application.grafana_agent[0].name
    endpoint = "grafana-dashboards-consumer"
  }

  application {
    offer_url = var.grafana_dashboard_consumer_offer_url
  }
  model_uuid = var.model_uuid
}

resource "juju_integration" "jimm_grafana_agent_logging" {
  count = var.logging_consumer_offer_url != null ? 1 : 0

  application {
    name     = juju_application.jimm.name
    endpoint = "logging"
  }

  application {
    name = juju_application.grafana_agent[0].name
  }
  model_uuid = var.model_uuid
}

resource "juju_integration" "jimm_grafana_agent_metric_endpoints" {
  count = var.metrics_endpoint_offer_url != null ? 1 : 0

  application {
    name     = juju_application.jimm.name
    endpoint = "metrics-endpoint"
  }

  application {
    name = juju_application.grafana_agent[0].name
  }
  model_uuid = var.model_uuid
}


resource "juju_integration" "jimm_grafana_agent_dashboard" {
  count = var.grafana_dashboard_consumer_offer_url != null ? 1 : 0

  application {
    name     = juju_application.jimm.name
    endpoint = "grafana-dashboard"
  }

  application {
    name = juju_application.grafana_agent[0].name
  }
  model_uuid = var.model_uuid
}

resource "juju_integration" "jimm_grafana_agent_tracing" {
  count = var.tracing_consumer_offer_url != null ? 1 : 0

  application {
    name     = juju_application.jimm.name
    endpoint = "tracing"
  }

  application {
    name     = juju_application.grafana_agent[0].name
    endpoint = "tracing-provider"
  }
  model_uuid = var.model_uuid
}

resource "juju_integration" "grafana_tracing_consumer" {
  count = var.tracing_consumer_offer_url != null ? 1 : 0

  application {
    name     = juju_application.grafana_agent[0].name
    endpoint = "tracing"
  }

  application {
    offer_url = var.tracing_consumer_offer_url
  }
  model_uuid = var.model_uuid
}
