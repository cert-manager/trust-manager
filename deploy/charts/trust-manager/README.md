# trust-manager

<!-- see https://artifacthub.io/packages/helm/cert-manager/trust-manager for the rendered version -->

## Helm Values

<!-- AUTO-GENERATED -->

### CRDs

#### **crds.enabled** ~ `bool`
> Default value:
> ```yaml
> true
> ```

This option decides if the CRDs should be installed as part of the Helm installation.
#### **crds.keep** ~ `bool`
> Default value:
> ```yaml
> true
> ```

This option makes it so that the "helm.sh/resource-policy": keep annotation is added to the CRD. This will prevent Helm from uninstalling the CRD when the Helm release is uninstalled. WARNING: when the CRDs are removed, all cert-manager custom resources  
(Certificates, Issuers, ...) will be removed too by the garbage collector.
### Trust Manager

#### **replicaCount** ~ `number,string,null`
> Default value:
> ```yaml
> 1
> ```

The number of replicas of trust-manager to run.  
  
For example:  
 Use integer to set a fixed number of replicas

```yaml
replicaCount: 2
```

Use null, if you want to omit the replicas field and use the Kubernetes default value.

```yaml
replicaCount: null
```

Use a string if you want to insert a variable for post-processing of the rendered template.

```yaml
replicaCount: ${REPLICAS_OVERRIDE:=3}
```



#### **nameOverride** ~ `string`
> Default value:
> ```yaml
> ""
> ```
#### **namespace** ~ `string`
> Default value:
> ```yaml
> ""
> ```

The namespace to install trust-manager into.  
If not set, the namespace of the release is used.  
This is helpful when installing trust-manager as a chart dependency (sub chart).
#### **imagePullSecrets** ~ `array`
> Default value:
> ```yaml
> []
> ```

For Private docker registries, authentication is needed. Registry secrets are applied to the service account.
#### **image.registry** ~ `string`

Target image registry. This value is prepended to the target image repository, if set.  
For example:

```yaml
registry: quay.io
repository: jetstack/trust-manager
```

#### **image.repository** ~ `string`
> Default value:
> ```yaml
> quay.io/jetstack/trust-manager
> ```

Target image repository.
#### **image.tag** ~ `string`

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion is used.

#### **image.digest** ~ `string`

Target image digest. Override any tag, if set.  
For example:

```yaml
digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20
```

#### **image.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

Kubernetes imagePullPolicy on Deployment.
#### **defaultPackage.enabled** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Whether to load the default trust package during pod initialization, and include it in main container args. This container enables the 'useDefaultCAs' source on Bundles.
#### **defaultPackage.resources** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Kubernetes pod resource limits for default package init container.  
  
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
#### **defaultPackageImage.registry** ~ `string`

Target image registry. This value is prepended to the target image repository, if set.  
For example:

```yaml
registry: quay.io
repository: jetstack/cert-manager-package-debian
```

#### **defaultPackageImage.repository** ~ `string`
> Default value:
> ```yaml
> quay.io/jetstack/cert-manager-package-debian
> ```

The repository for the default package image. This image enables the 'useDefaultCAs' source on Bundles.
#### **defaultPackageImage.tag** ~ `string`
> Default value:
> ```yaml
> "20210119.0"
> ```

Override the image tag of the default package image. If no value is set, the chart's appVersion is used.

#### **defaultPackageImage.digest** ~ `string`

Target image digest. Override any tag, if set.  
For example:

```yaml
digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20
```

#### **defaultPackageImage.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

imagePullPolicy for the default package image.
#### **secretTargets.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

If set to true, enable writing trust bundles to Kubernetes Secrets as a target. trust-manager can only write to secrets which are explicitly allowed via either authorizedSecrets or authorizedSecretsAll. Note that enabling secret targets will grant trust-manager read access to all secrets in the cluster.
#### **secretTargets.authorizedSecretsAll** ~ `bool`
> Default value:
> ```yaml
> false
> ```

If set to true, grant read/write permission to all secrets across the cluster. Use with caution!  
If set, ignores the authorizedSecrets list.
#### **secretTargets.authorizedSecrets** ~ `array`
> Default value:
> ```yaml
> []
> ```

A list of secret names which trust-manager will be permitted to read and write across all namespaces. These are the only allowable Secrets that can be used as targets. If the list is empty (and authorizedSecretsAll is false), trust-manager can't write to secrets and can only read secrets in the trust namespace for use as sources.
#### **resources** ~ `object`
> Default value:
> ```yaml
> {}
> ```

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
#### **priorityClassName** ~ `string`
> Default value:
> ```yaml
> ""
> ```

Configure the priority class of the pod. For more information, see [PriorityClass](https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/#priorityclass).
#### **nodeSelector** ~ `object`
> Default value:
> ```yaml
> kubernetes.io/os: linux
> ```

Configure the nodeSelector; defaults to any Linux node (trust-manager doesn't support Windows nodes)

#### **affinity** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Kubernetes Affinity. For more information, see [Affinity v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#affinity-v1-core).  
For example:

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
#### **tolerations** ~ `array`
> Default value:
> ```yaml
> []
> ```

List of Kubernetes Tolerations, if required. For more information, see [Toleration v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core).  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```
#### **topologySpreadConstraints** ~ `array`
> Default value:
> ```yaml
> []
> ```

List of Kubernetes TopologySpreadConstraints. For more information, see [TopologySpreadConstraint v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#topologyspreadconstraint-v1-core).  
For example:

```yaml
topologySpreadConstraints:
- maxSkew: 2
  topologyKey: topology.kubernetes.io/zone
  whenUnsatisfiable: ScheduleAnyway
  labelSelector:
    matchLabels:
      app.kubernetes.io/name: trust-manager
```
#### **filterExpiredCertificates.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Whether to filter expired certificates from the trust bundle.
#### **app.logFormat** ~ `string`
> Default value:
> ```yaml
> text
> ```

The format of trust-manager logging. Accepted values are text or json.
#### **app.logLevel** ~ `number`
> Default value:
> ```yaml
> 1
> ```

The verbosity of trust-manager logging. This takes a value from 1-5, with the higher value being more verbose.
#### **app.leaderElection.leaseDuration** ~ `string`
> Default value:
> ```yaml
> 15s
> ```

The duration that non-leader candidates will wait to force acquire leadership. The default should be sufficient in a healthy cluster but can be slightly increased to prevent trust-manager from restart-looping when the API server is overloaded.
#### **app.leaderElection.renewDeadline** ~ `string`
> Default value:
> ```yaml
> 10s
> ```

The interval between attempts by the acting leader to renew a leadership slot before it stops leading. This MUST be less than or equal to the lease duration. The default should be sufficient in a healthy cluster but can be slightly increased to prevent trust-manager from restart-looping when the API server is overloaded.
#### **app.readinessProbe.port** ~ `number`
> Default value:
> ```yaml
> 6060
> ```

The container port on which to expose the trust-manager HTTP readiness probe using the default network interface.
#### **app.readinessProbe.path** ~ `string`
> Default value:
> ```yaml
> /readyz
> ```

The path on which to expose the trust-manager HTTP readiness probe using the default network interface.
#### **app.trust.namespace** ~ `string`
> Default value:
> ```yaml
> cert-manager
> ```

The namespace used as the trust source. Note that the namespace _must_ exist before installing trust-manager.
#### **app.securityContext.seccompProfileEnabled** ~ `bool`
> Default value:
> ```yaml
> true
> ```

If false, disables the default seccomp profile, which might be required to run on certain platforms.
#### **app.podLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Pod labels to add to trust-manager pods.
#### **app.podAnnotations** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Pod annotations to add to trust-manager pods.
### Webhook

#### **app.webhook.host** ~ `string`
> Default value:
> ```yaml
> 0.0.0.0
> ```

Host that the webhook listens on.
#### **app.webhook.port** ~ `number`
> Default value:
> ```yaml
> 6443
> ```

Port that the webhook listens on.
#### **app.webhook.timeoutSeconds** ~ `number`
> Default value:
> ```yaml
> 5
> ```

Timeout of webhook HTTP request.
#### **app.webhook.service.type** ~ `string`
> Default value:
> ```yaml
> ClusterIP
> ```

The type of Kubernetes Service used by the Webhook.
#### **app.webhook.service.ipFamilyPolicy** ~ `string`
> Default value:
> ```yaml
> ""
> ```

Set the ip family policy to configure dual-stack see [Configure dual-stack](https://kubernetes.io/docs/concepts/services-networking/dual-stack/#services)
#### **app.webhook.service.ipFamilies** ~ `array`
> Default value:
> ```yaml
> []
> ```

Sets the families that should be supported and the order in which they should be applied to ClusterIP as well. Can be IPv4 and/or IPv6.
#### **app.webhook.service.nodePort** ~ `number`

The nodePort set on the Service used by the webhook.

#### **app.webhook.tls.helmCert.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Whether to issue a webhook cert using Helm, which removes the need to install cert-manager. Helm-issued certificates can be challenging to rotate and maintain, and the issued cert will have a duration of 10 years and be modified when trust-manager is updated. It's safer and easier to rely on cert-manager for issuing the webhook cert - avoid using Helm-generated certs in production.
#### **app.webhook.tls.approverPolicy.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Whether to create an approver-policy CertificateRequestPolicy allowing auto-approval of the trust-manager webhook certificate. If you have approver-policy installed, you almost certainly want to enable this.
#### **app.webhook.tls.approverPolicy.certManagerNamespace** ~ `string`
> Default value:
> ```yaml
> cert-manager
> ```

The namespace in which cert-manager was installed. Only used if `app.webhook.tls.approverPolicy.enabled` is true.
#### **app.webhook.tls.approverPolicy.certManagerServiceAccount** ~ `string`
> Default value:
> ```yaml
> cert-manager
> ```

The name of cert-manager's Service Account. Only used if `app.webhook.tls.approverPolicy.enabled` is true.
#### **app.webhook.hostNetwork** ~ `bool`
> Default value:
> ```yaml
> false
> ```

This value specifies if the app should be started in hostNetwork mode. It is required for use in some managed Kubernetes clusters (such as AWS EKS) with custom CNI.
### Metrics

#### **app.metrics.port** ~ `number`
> Default value:
> ```yaml
> 9402
> ```

The port for exposing Prometheus metrics on 0.0.0.0 on path '/metrics'.
#### **app.metrics.service.enabled** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Create a Service resource to expose the metrics endpoint.
#### **app.metrics.service.type** ~ `string`
> Default value:
> ```yaml
> ClusterIP
> ```

The Service type to expose metrics.
#### **app.metrics.service.ipFamilyPolicy** ~ `string`
> Default value:
> ```yaml
> ""
> ```

Set the ip family policy to configure dual-stack see [Configure dual-stack](https://kubernetes.io/docs/concepts/services-networking/dual-stack/#services)
#### **app.metrics.service.ipFamilies** ~ `array`
> Default value:
> ```yaml
> []
> ```

Sets the families that should be supported and the order in which they should be applied to ClusterIP as well. Can be IPv4 and/or IPv6.
#### **app.metrics.service.servicemonitor.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Create a Prometheus ServiceMonitor for trust-manager.
#### **app.metrics.service.servicemonitor.prometheusInstance** ~ `string`
> Default value:
> ```yaml
> default
> ```

Sets the value of the "prometheus" label on the ServiceMonitor. This is used so that separate Prometheus instances can select different ServiceMonitors using labels.
#### **app.metrics.service.servicemonitor.interval** ~ `string`
> Default value:
> ```yaml
> 10s
> ```

The interval to scrape the metrics.
#### **app.metrics.service.servicemonitor.scrapeTimeout** ~ `string`
> Default value:
> ```yaml
> 5s
> ```

The timeout for a metrics scrape.
#### **app.metrics.service.servicemonitor.labels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Additional labels to add to the ServiceMonitor.
#### **podDisruptionBudget.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Enable or disable the PodDisruptionBudget resource.  
  
This prevents downtime during voluntary disruptions such as during a Node upgrade. For example, the PodDisruptionBudget will block `kubectl drain` if it is used on the Node where the only remaining trust-manager  
Pod is currently running.
#### **podDisruptionBudget.minAvailable** ~ `unknown`

This configures the minimum available pods for disruptions. It can either be set to an integer (e.g. 1) or a percentage value (e.g. 25%).  
It cannot be used if `maxUnavailable` is set.


#### **podDisruptionBudget.maxUnavailable** ~ `unknown`

This configures the maximum unavailable pods for disruptions. It can either be set to an integer (e.g. 1) or a percentage value (e.g. 25%). it cannot be used if `minAvailable` is set.


#### **commonLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Labels to apply to all resources

<!-- /AUTO-GENERATED -->