# trust-manager

![Version: v0.7.1](https://img.shields.io/badge/Version-v0.7.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v0.7.1](https://img.shields.io/badge/AppVersion-v0.7.1-informational?style=flat-square)

trust-manager is the easiest way to manage TLS trust bundles in Kubernetes and OpenShift clusters

**Homepage:** <https://github.com/cert-manager/trust-manager>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| cert-manager-maintainers | <cert-manager-maintainers@googlegroups.com> | <https://cert-manager.io> |

## Source Code

* <https://github.com/cert-manager/trust-manager>

## Requirements

Kubernetes: `>= 1.25.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Kubernetes Affinty; see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#affinity-v1-core |
| app.logLevel | int | `1` | Verbosity of trust-manager logging; takes a value from 1-5, with higher being more verbose |
| app.metrics.port | int | `9402` | Port for exposing Prometheus metrics on 0.0.0.0 on path '/metrics'. |
| app.metrics.service | object | `{"enabled":true,"servicemonitor":{"enabled":false,"interval":"10s","labels":{},"prometheusInstance":"default","scrapeTimeout":"5s"},"type":"ClusterIP"}` | Service to expose metrics endpoint. |
| app.metrics.service.enabled | bool | `true` | Create a Service resource to expose metrics endpoint. |
| app.metrics.service.servicemonitor | object | `{"enabled":false,"interval":"10s","labels":{},"prometheusInstance":"default","scrapeTimeout":"5s"}` | ServiceMonitor resource for this Service. |
| app.metrics.service.type | string | `"ClusterIP"` | Service type to expose metrics. |
| app.readinessProbe.path | string | `"/readyz"` | Path on which to expose trust-manager HTTP readiness probe using default network interface. |
| app.readinessProbe.port | int | `6060` | Container port on which to expose trust-manager HTTP readiness probe using default network interface. |
| app.securityContext.seccompProfileEnabled | bool | `true` | If false, disables the default seccomp profile, which might be required to run on certain platforms |
| app.trust.namespace | string | `"cert-manager"` | Namespace used as trust source. Note that the namespace _must_ exist before installing trust-manager. |
| app.webhook.host | string | `"0.0.0.0"` | Host that the webhook listens on. |
| app.webhook.hostNetwork | bool | `false` | Specifies if the app should be started in hostNetwork mode. Required for use in some managed kubernetes clusters (such as AWS EKS) with custom CNI. |
| app.webhook.port | int | `6443` | Port that the webhook listens on. |
| app.webhook.service | object | `{"type":"ClusterIP"}` | Type of Kubernetes Service used by the Webhook |
| app.webhook.timeoutSeconds | int | `5` | Timeout of webhook HTTP request. |
| app.webhook.tls.approverPolicy.certManagerNamespace | string | `"cert-manager"` | Namespace in which cert-manager was installed. Only used if app.webhook.tls.approverPolicy.enabled is true |
| app.webhook.tls.approverPolicy.certManagerServiceAccount | string | `"cert-manager"` | Name of cert-manager's ServiceAccount. Only used if app.webhook.tls.approverPolicy.enabled is true |
| app.webhook.tls.approverPolicy.enabled | bool | `false` | Whether to create an approver-policy CertificateRequestPolicy allowing auto-approval of the trust-manager webhook certificate. If you have approver-policy installed, you almost certainly want to enable this. |
| crds.enabled | bool | `true` | Whether or not to install the crds. |
| defaultPackage.enabled | bool | `true` | Whether to load the default trust package during pod initialization and include it in main container args. This container enables the 'useDefaultCAs' source on Bundles. |
| defaultPackageImage.digest | string | `nil` | Target image digest. Will override any tag if set. for example: digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20 |
| defaultPackageImage.pullPolicy | string | `"IfNotPresent"` | imagePullPolicy for the default package image |
| defaultPackageImage.registry | string | `nil` | Target image registry. Will be prepended to the target image repositry if set. |
| defaultPackageImage.repository | string | `"quay.io/jetstack/cert-manager-package-debian"` | Repository for the default package image. This image enables the 'useDefaultCAs' source on Bundles. |
| defaultPackageImage.tag | string | `"20210119.0"` | Tag for the default package image |
| image.digest | string | `nil` | Target image digest. Will override any tag if set. for example: digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20 |
| image.pullPolicy | string | `"IfNotPresent"` | Kubernetes imagePullPolicy on Deployment. |
| image.registry | string | `nil` | Target image registry. Will be prepended to the target image repositry if set. |
| image.repository | string | `"quay.io/jetstack/trust-manager"` | Target image repository. |
| image.tag | string | `nil` | Target image version tag. Defaults to the chart's appVersion. |
| imagePullSecrets | list | `[]` | For Private docker registries, authentication is needed. Registry secrets are applied to the service account |
| namespace | string | `""` | The namespace to install trust-manager into. If not set, the namespace of the release will be used. This is helpful when installing trust-manager as a chart dependency (sub chart) |
| nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Configure the nodeSelector; defaults to any Linux node (trust-manager doesn't support Windows nodes) |
| priorityClassName | string | `""` | Configure the priority class of the pod; see https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/#priorityclass |
| replicaCount | int | `1` | Number of replicas of trust-manager to run. |
| resources | object | `{}` |  |
| secretTargets.authorizedSecrets | list | `[]` | A list of secret names which trust-manager will be permitted to read and write across all namespaces. These will be the only allowable Secrets that can be used as targets. If the list is empty (and authorizedSecretsAll is false), trust-manager will not be able to write to secrets and will only be able to read secrets in the trust namespace for use as sources. |
| secretTargets.authorizedSecretsAll | bool | `false` | If set to true, grant read/write permission to all secrets across the cluster. Use with caution! If set, ignores the authorizedSecrets list. |
| secretTargets.enabled | bool | `false` | If set to true, enable writing trust bundles to Kubernetes Secrets as a target. trust-manager can only write to secrets which are explicitly allowed via either authorizedSecrets or authorizedSecretsAll. NOTE: Enabling secret targets will grant trust-manager read access to all secrets in the cluster. |
| tolerations | list | `[]` | List of Kubernetes Tolerations; see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core |
| topologySpreadConstraints | list | `[]` | List of Kubernetes TopologySpreadConstraints; see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#topologyspreadconstraint-v1-core |
