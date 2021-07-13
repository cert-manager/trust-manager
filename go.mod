module github.com/cert-manager/trust

go 1.16

require (
	github.com/go-logr/logr v0.4.0
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	k8s.io/api v0.21.2
	k8s.io/apimachinery v0.21.2
	k8s.io/cli-runtime v0.21.2
	k8s.io/client-go v0.21.2
	k8s.io/code-generator v0.21.2
	k8s.io/component-base v0.21.2
	k8s.io/klog/v2 v2.8.0
	k8s.io/utils v0.0.0-20210527160623-6fdb442a123b
	sigs.k8s.io/controller-runtime v0.9.2
	sigs.k8s.io/controller-tools v0.6.1
)
