# Add these to your data resources section
data "juju_offer" "logging_consumer" {
  url = var.logging_consumer_offer_url
}

data "juju_offer" "metrics_endpoint" {
  url = var.metrics_endpoint_offer_url
}

data "juju_offer" "grafana_dashboard_consumer" {
  url = var.grafana_dashboard_consumer_offer_url
}

# Add these integration resources
resource "juju_integration" "grafana_metrics_endpoint" {
  model = juju_model.jimm.name

  application {
    name     = juju_application.grafana_agent.name
    endpoint = "metrics-endpoint"
  }

  application {
    offer_url = data.juju_offer.metrics_endpoint.url
  }
}

resource "juju_integration" "grafana_logging_consumer" {
  model = juju_model.jimm.name

  application {
    name     = juju_application.grafana_agent
    endpoint = "logging-consumer"
  }

  application {
    offer_url = data.juju_offer.logging_consumer.url
  }
}

resource "juju_integration" "grafana_dashboard_consumer" {
  model = juju_model.jimm.name

  application {
    name     = juju_application.grafana_agent.name
    endpoint = "grafana-dashboards-consumer"
  }

  application {
    offer_url = data.juju_offer.grafana_dashboard_consumer.url
  }
}

resource "juju_integration" "jimm_grafana_agent_logging" {
  model = juju_model.jimm.name

  application {
    name     = juju_application.jimm.name
    endpoint = "logging"
  }

  application {
    name = juju_application.grafana_agent.name
  }
}

resource "juju_integration" "jimm_grafana_agent_metric_endpoints" {
  model = juju_model.jimm.name

  application {
    name     = juju_application.jimm.name
    endpoint = "metrics-endpoint"
  }

  application {
    name = juju_application.grafana_agent.name
  }
}


resource "juju_integration" "jimm_grafana_agent_dashboard" {
  model = juju_model.jimm.name

  application {
    name     = juju_application.jimm.name
    endpoint = "grafana-dashboard"
  }

  application {
    name = juju_application.grafana_agent.name
  }
}
