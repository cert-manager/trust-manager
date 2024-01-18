# trust-manager

![Version: v0.8.0](https://img.shields.io/badge/Version-v0.8.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v0.8.0](https://img.shields.io/badge/AppVersion-v0.8.0-informational?style=flat-square)

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

<!-- AUTO-GENERATED -->

### CRDs


<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>crds.enabled</td>
<td>

Whether or not to install the CRDs.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
</table>

### Trust Manager


<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>replicaCount</td>
<td>

Number of replicas of trust-manager to run.

</td>
<td>number</td>
<td>

```yaml
1
```

</td>
</tr>
<tr>

<td>namespace</td>
<td>

The namespace to install trust-manager into.  
If not set, the namespace of the release will be used. This is helpful when installing trust-manager as a chart dependency (sub chart)

</td>
<td>string</td>
<td>

```yaml
""
```

</td>
</tr>
<tr>

<td>imagePullSecrets</td>
<td>

For Private docker registries, authentication is needed. Registry secrets are applied to the service account

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>image.repository</td>
<td>

Target image repository.

</td>
<td>string</td>
<td>

```yaml
quay.io/jetstack/trust-manager
```

</td>
</tr>
<tr>

<td>image.registry</td>
<td>

Target image registry. Will be prepended to the target image repository if set.


</td>
<td>string</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>image.tag</td>
<td>

Target image version tag. Defaults to the chart's appVersion.


</td>
<td>string</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>image.digest</td>
<td>

Target image digest. Will override any tag if set. for example:

```yaml
digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20
```


</td>
<td>string</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>image.pullPolicy</td>
<td>

Kubernetes imagePullPolicy on Deployment.

</td>
<td>string</td>
<td>

```yaml
IfNotPresent
```

</td>
</tr>
<tr>

<td>defaultPackage.enabled</td>
<td>

Whether to load the default trust package during pod initialization and include it in main container args. This container enables the 'useDefaultCAs' source on Bundles.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>defaultPackageImage.repository</td>
<td>

Repository for the default package image. This image enables the 'useDefaultCAs' source on Bundles.

</td>
<td>string</td>
<td>

```yaml
quay.io/jetstack/cert-manager-package-debian
```

</td>
</tr>
<tr>

<td>defaultPackageImage.registry</td>
<td>

Target image registry. Will be prepended to the target image repository if set.


</td>
<td>string</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>defaultPackageImage.tag</td>
<td>

Tag for the default package image

</td>
<td>string</td>
<td>

```yaml
"20210119.0"
```

</td>
</tr>
<tr>

<td>defaultPackageImage.digest</td>
<td>

Target image digest. Will override any tag if set. for example:

```yaml
digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20
```


</td>
<td>string</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>defaultPackageImage.pullPolicy</td>
<td>

imagePullPolicy for the default package image

</td>
<td>string</td>
<td>

```yaml
IfNotPresent
```

</td>
</tr>
<tr>

<td>secretTargets.enabled</td>
<td>

If set to true, enable writing trust bundles to Kubernetes Secrets as a target. trust-manager can only write to secrets which are explicitly allowed via either authorizedSecrets or authorizedSecretsAll. NOTE: Enabling secret targets will grant trust-manager read access to all secrets in the cluster.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>secretTargets.authorizedSecretsAll</td>
<td>

If set to true, grant read/write permission to all secrets across the cluster. Use with caution!  
If set, ignores the authorizedSecrets list.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>secretTargets.authorizedSecrets</td>
<td>

A list of secret names which trust-manager will be permitted to read and write across all namespaces. These will be the only allowable Secrets that can be used as targets. If the list is empty (and authorizedSecretsAll is false), trust-manager will not be able to write to secrets and will only be able to read secrets in the trust namespace for use as sources.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>resources</td>
<td>

Kubernetes pod resource limits for trust.  
  
For example:

```yaml
resources:
  limits:
    cpu: 100m
    memory: 128Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>priorityClassName</td>
<td>

Configure the priority class of the pod; see https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/#priorityclass

</td>
<td>string</td>
<td>

```yaml
""
```

</td>
</tr>
<tr>

<td>nodeSelector</td>
<td>

Configure the nodeSelector; defaults to any Linux node (trust-manager doesn't support Windows nodes)


</td>
<td>object</td>
<td>

```yaml
kubernetes.io/os: linux
```

</td>
</tr>
<tr>

<td>affinity</td>
<td>

Kubernetes Affinty; see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#affinity-v1-core for example:

```yaml
affinity:
  nodeAffinity:
   requiredDuringSchedulingIgnoredDuringExecution:
     nodeSelectorTerms:
     - matchExpressions:
       - key: foo.bar.com/role
         operator: In
         values:
         - master
```

Kubernetes Affinty; see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#affinity-v1-core

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>tolerations</td>
<td>

List of Kubernetes Tolerations, if required; see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core for example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```

List of Kubernetes Tolerations; see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>topologySpreadConstraints</td>
<td>

List of Kubernetes TopologySpreadConstraints; see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#topologyspreadconstraint-v1-core  
For example:

```yaml
topologySpreadConstraints:
- maxSkew: 2
  topologyKey: topology.kubernetes.io/zone
  whenUnsatisfiable: ScheduleAnyway
  labelSelector:
    matchLabels:
      app.kubernetes.io/instance: cert-manager
      app.kubernetes.io/component: controller
```

List of Kubernetes TopologySpreadConstraints; see https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#topologyspreadconstraint-v1-core

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>filterExpiredCertificates.enabled</td>
<td>

Whether to filter expired certificates from the trust bundle.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>app.logLevel</td>
<td>

Verbosity of trust-manager logging; takes a value from 1-5, with higher being more verbose

</td>
<td>number</td>
<td>

```yaml
1
```

</td>
</tr>
<tr>

<td>app.readinessProbe.port</td>
<td>

Container port on which to expose trust-manager HTTP readiness probe using default network interface.

</td>
<td>number</td>
<td>

```yaml
6060
```

</td>
</tr>
<tr>

<td>app.readinessProbe.path</td>
<td>

Path on which to expose trust-manager HTTP readiness probe using default network interface.

</td>
<td>string</td>
<td>

```yaml
/readyz
```

</td>
</tr>
<tr>

<td>app.trust.namespace</td>
<td>

Namespace used as trust source. Note that the namespace _must_ exist before installing trust-manager.

</td>
<td>string</td>
<td>

```yaml
cert-manager
```

</td>
</tr>
<tr>

<td>app.securityContext.seccompProfileEnabled</td>
<td>

If false, disables the default seccomp profile, which might be required to run on certain platforms

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>app.podLabels</td>
<td>

Pod labels to add to trust-manager pods.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>app.podAnnotations</td>
<td>

Pod annotations to add to trust-manager pods.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
</table>

### Webhook


<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>app.webhook.host</td>
<td>

Host that the webhook listens on.

</td>
<td>string</td>
<td>

```yaml
0.0.0.0
```

</td>
</tr>
<tr>

<td>app.webhook.port</td>
<td>

Port that the webhook listens on.

</td>
<td>number</td>
<td>

```yaml
6443
```

</td>
</tr>
<tr>

<td>app.webhook.timeoutSeconds</td>
<td>

Timeout of webhook HTTP request.

</td>
<td>number</td>
<td>

```yaml
5
```

</td>
</tr>
<tr>

<td>app.webhook.service.type</td>
<td>

Type of Kubernetes Service used by the Webhook

</td>
<td>string</td>
<td>

```yaml
ClusterIP
```

</td>
</tr>
<tr>

<td>app.webhook.tls.approverPolicy.enabled</td>
<td>

Whether to create an approver-policy CertificateRequestPolicy allowing auto-approval of the trust-manager webhook certificate. If you have approver-policy installed, you almost certainly want to enable this.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>app.webhook.tls.approverPolicy.certManagerNamespace</td>
<td>

Namespace in which cert-manager was installed. Only used if app.webhook.tls.approverPolicy.enabled is true

</td>
<td>string</td>
<td>

```yaml
cert-manager
```

</td>
</tr>
<tr>

<td>app.webhook.tls.approverPolicy.certManagerServiceAccount</td>
<td>

Name of cert-manager's ServiceAccount. Only used if app.webhook.tls.approverPolicy.enabled is true

</td>
<td>string</td>
<td>

```yaml
cert-manager
```

</td>
</tr>
<tr>

<td>app.webhook.hostNetwork</td>
<td>

Specifies if the app should be started in hostNetwork mode. Required for use in some managed kubernetes clusters (such as AWS EKS) with custom CNI.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
</table>

### Metrics


<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>app.metrics.port</td>
<td>

Port for exposing Prometheus metrics on 0.0.0.0 on path '/metrics'.

</td>
<td>number</td>
<td>

```yaml
9402
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor</td>
<td>

Create a Service resource to expose metrics endpoint.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor</td>
<td>

Service type to expose metrics.

</td>
<td>string</td>
<td>

```yaml
ClusterIP
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.enabled</td>
<td>

Create a Prometheus ServiceMonitor for trust-manager

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.prometheusInstance</td>
<td>

Sets the value of the "prometheus" label on the ServiceMonitor, this is used as separate Prometheus instances can select difference  
ServiceMonitors using labels

</td>
<td>string</td>
<td>

```yaml
default
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.interval</td>
<td>

Interval to scrape the metrics

</td>
<td>string</td>
<td>

```yaml
10s
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.scrapeTimeout</td>
<td>

Timeout for a metrics scrape

</td>
<td>string</td>
<td>

```yaml
5s
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.labels</td>
<td>

Additional labels to add to the ServiceMonitor

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
</table>

<!-- /AUTO-GENERATED -->