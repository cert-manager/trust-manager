# trust-manager

![Version: v0.6.0](https://img.shields.io/badge/Version-v0.6.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v0.6.0](https://img.shields.io/badge/AppVersion-v0.6.0-informational?style=flat-square)

trust-manager is the easiest way to manage TLS trust bundles in Kubernetes and OpenShift clusters

**Homepage:** <https://github.com/cert-manager/trust-manager>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| cert-manager-maintainers | <cert-manager-maintainers@googlegroups.com> | <https://cert-manager.io> |

## Source Code

* <https://github.com/cert-manager/trust-manager>

## Requirements

Kubernetes: `>= 1.22.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Kubernetes Affinty; see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#affinity-v1-core |
| app.logLevel | int | `1` | Verbosity of trust logging; takes a value from 1-5, with higher being more verbose |
| app.metrics.port | int | `9402` | Port for exposing Prometheus metrics on 0.0.0.0 on path '/metrics'. |
| app.metrics.service | object | `{"enabled":true,"servicemonitor":{"enabled":false,"interval":"10s","labels":{},"prometheusInstance":"default","scrapeTimeout":"5s"},"type":"ClusterIP"}` | Service to expose metrics endpoint. |
| app.metrics.service.enabled | bool | `true` | Create a Service resource to expose metrics endpoint. |
| app.metrics.service.servicemonitor | object | `{"enabled":false,"interval":"10s","labels":{},"prometheusInstance":"default","scrapeTimeout":"5s"}` | ServiceMonitor resource for this Service. |
| app.metrics.service.type | string | `"ClusterIP"` | Service type to expose metrics. |
| app.readinessProbe.path | string | `"/readyz"` | Path on which to expose trust HTTP readiness probe using default network interface. |
| app.readinessProbe.port | int | `6060` | Container port on which to expose trust HTTP readiness probe using default network interface. |
| app.securityContext.seccompProfileEnabled | bool | `true` | If false, disables the default seccomp profile, which might be required to run on certain platforms |
| app.trust.namespace | string | `"cert-manager"` | Namespace used as trust source. Note that the namespace _must_ exist before installing trust-manager. |
| app.webhook.host | string | `"0.0.0.0"` | Host that the webhook listens on. |
| app.webhook.port | int | `6443` | Port that the webhook listens on. |
| app.webhook.service | object | `{"type":"ClusterIP"}` | Type of Kubernetes Service used by the Webhook |
| app.webhook.timeoutSeconds | int | `5` | Timeout of webhook HTTP request. |
| app.webhook.tls.approverPolicy.certManagerNamespace | string | `"cert-manager"` | Namespace in which cert-manager was installed. Only used if approverPolicy has been enabled. |
| app.webhook.tls.approverPolicy.enabled | bool | `false` | Whether to create an approver-policy CertificateRequestPolicy allowing auto-approval of the trust-manager webhook certificate. If you have approver-policy installed, you almost certainly want to enable this. |
| crds.enabled | bool | `true` | Whether or not to install the crds. |
| defaultPackage.enabled | bool | `true` | Whether to load the default trust package during pod initialization and include it in main container args. This container enables the 'useDefaultCAs' source on Bundles. |
| defaultPackageImage.pullPolicy | string | `"IfNotPresent"` | imagePullPolicy for the default package image |
| defaultPackageImage.repository | string | `"quay.io/jetstack/cert-manager-package-debian"` | Repository for the default package image. This image enables the 'useDefaultCAs' source on Bundles. |
| defaultPackageImage.tag | string | `"20210119.0"` | Tag for the default package image |
| image.pullPolicy | string | `"IfNotPresent"` | Kubernetes imagePullPolicy on Deployment. |
| image.repository | string | `"quay.io/jetstack/trust-manager"` | Target image repository. |
| image.tag | string | `"v0.6.0"` | Target image version tag. |
| imagePullSecrets | list | `[]` | For Private docker registries, authentication is needed. Registry secrets are applied to the service account |
| nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Configure the nodeSelector; defaults to any Linux node (trust-manager doesn't support Windows nodes) |
| replicaCount | int | `1` | Number of replicas of trust to run. |
| resources | object | `{}` |  |
| tolerations | list | `[]` | List of Kubernetes Tolerations; see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core |
| topologySpreadConstraints | list | `[]` | List of Kubernetes TopologySpreadConstraints; see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#topologyspreadconstraint-v1-core |

