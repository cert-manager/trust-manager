# cert-manager-trust

> **:exclamation: This Helm Chart is deprecated!**

![Version: v0.2.1](https://img.shields.io/badge/Version-v0.2.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v0.2.0](https://img.shields.io/badge/AppVersion-v0.2.0-informational?style=flat-square)

DEPRECATED: The old name for trust-manager. Use the 'trust-manager' chart instead.

**Homepage:** <https://github.com/cert-manager/trust-manager>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| cert-manager-maintainers | <cert-manager-maintainers@googlegroups.com> | <https://cert-manager.io> |

## Source Code

* <https://github.com/cert-manager/trust-manager>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| app.logLevel | int | `1` | Verbosity of trust logging; takes a value from 1-5, with higher being more verbose |
| app.metrics.port | int | `9402` | Port for exposing Prometheus metrics on 0.0.0.0 on path '/metrics'. |
| app.metrics.service | object | `{"enabled":true,"servicemonitor":{"enabled":false,"interval":"10s","labels":{},"prometheusInstance":"default","scrapeTimeout":"5s"},"type":"ClusterIP"}` | Service to expose metrics endpoint. |
| app.metrics.service.enabled | bool | `true` | Create a Service resource to expose metrics endpoint. |
| app.metrics.service.servicemonitor | object | `{"enabled":false,"interval":"10s","labels":{},"prometheusInstance":"default","scrapeTimeout":"5s"}` | ServiceMonitor resource for this Service. |
| app.metrics.service.type | string | `"ClusterIP"` | Service type to expose metrics. |
| app.readinessProbe.path | string | `"/readyz"` | Path on which to expose trust HTTP readiness probe using default network interface. |
| app.readinessProbe.port | int | `6060` | Container port on which to expose trust HTTP readiness probe using default network interface. |
| app.trust.namespace | string | `"cert-manager"` | Namespace used as trust source. Note that the namespace _must_ exist before installing cert-manager/trust. |
| app.webhook.host | string | `"0.0.0.0"` | Host that the webhook listens on. |
| app.webhook.port | int | `6443` | Port that the webhook listens on. |
| app.webhook.service | object | `{"type":"ClusterIP"}` | Type of Kubernetes Service used by the Webhook |
| app.webhook.timeoutSeconds | int | `5` | Timeout of webhook HTTP request. |
| image.pullPolicy | string | `"IfNotPresent"` | Kubernetes imagePullPolicy on Deployment. |
| image.repository | string | `"quay.io/jetstack/cert-manager-trust"` | Target image repository. |
| image.tag | string | `"v0.2.0"` | Target image version tag. |
| imagePullSecrets | list | `[]` | For Private docker registries, authentication is needed. Registry secrets are applied to the service account |
| replicaCount | int | `1` | Number of replicas of trust to run. |
| resources | object | `{}` |  |

