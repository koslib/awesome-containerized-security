# awesome-containerized-security
A collection of tools to improve your containerized apps security posture.

This aspires to be a curated list of awesome tools you can use in order to improve your security posture. The focus is on containerized applications. 

Want to add something? Open a PR :) 

> Github Action examples coming soon, providing easy-to-use examples for your CI pipeline

## Static code analysis

- [semgrep](https://semgrep.dev/)
- [sonarqube](https://www.sonarqube.org/)
- [deepsource](https://deepsource.io/)
- [embold](https://embold.io/)
- [OWASP code crawler](https://wiki.owasp.org/index.php/Category:OWASP_Code_Crawler)
- [OWASP Orizon](https://wiki.owasp.org/index.php/Category:OWASP_Orizon_Project)
- [snyk code](https://snyk.io/product/snyk-code/)


## Image scanning / Registry

- [docker scan](https://docs.docker.com/engine/scan/)
- [AWS ECR Image Scanning](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html)
- [Azure Container Registry scanning](https://azure.microsoft.com/en-us/updates/vulnerability-scanning-for-images-in-azure-container-registry-is-now-generally-available/)
- [opa-docker-authz](https://github.com/open-policy-agent/opa-docker-authz) policy-enabled authorization plugin for Docker
- [cosign](https://github.com/sigstore/cosign) Container Signing, Verification and Storage in an OCI registry.


## Container Scanning

- [snyk](https://snyk.io/product/container-vulnerability-management/)
- [google cloud Container Scanning](https://cloud.google.com/container-analysis/docs/container-scanning-overview)
- [gitlab container scanning](https://docs.gitlab.com/ee/user/application_security/container_scanning/)
- [clair](https://github.com/quay/clair)
- [docker bench security](https://github.com/docker/docker-bench-security)
- [dagda](https://github.com/eliasgranderubio/dagda/)
- [harbor](https://goharbor.io/)
- [jfrog xray](https://jfrog.com/xray/)
- [qualys](https://www.qualys.com/apps/container-security/)
- [aquasec](https://www.aquasec.com/products/container-vulnerability-scanning/)
- [twistlock](https://www.esecurityplanet.com/products/twistlock/)
- [trivy](https://github.com/aquasecurity/trivy)
- [grype](https://github.com/anchore/grype)


## Container Security Tools

- [kyverno](https://kyverno.io/)
- [falco](https://falco.org/)
- [cert-manager](https://cert-manager.io/docs/)
- [anchore](https://anchore.com/opensource/)
- [ksniff](https://github.com/eldadru/ksniff) sniff k8s pods traffic
- [k8s pod security policies](https://kubernetes.io/docs/concepts/security/pod-security-policy/)
- [secret-diver](https://github.com/cider-rnd/secret-diver) analyzes secrets in containers
- [oci-seccomp-bpf-hook](https://github.com/containers/oci-seccomp-bpf-hook) OCI hook to trace syscalls and generate a seccomp profile


## Kubernetes cluster security

- [neuvector](https://github.com/neuvector/neuvector) NeuVector is a kubernetes-native container security platform that delivers complete zero trust container security
- [kube-hunter](https://github.com/aquasecurity/kube-hunter)
- [k8s network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eksuser](https://github.com/prabhatsharma/eksuser/)
- [gatekeeper](https://github.com/open-policy-agent/gatekeeper)
- [kube-bench](https://github.com/aquasecurity/kube-bench)
- [kube-scan](https://github.com/octarinesec/kube-scan) cluster risk assessment
- [teleport](https://github.com/gravitational/teleport)
- [kubescape](https://github.com/armosec/kubescape) misconfiguration scanning
- [datree](https://github.com/datreeio/datree) E2E policy enforcement solution
- [kubeshark](https://github.com/kubeshark/kubeshark) think TCPDump and Wireshark re-invented for Kubernetes
- [KubeHound](https://github.com/DataDog/KubeHound) is a Kubernetes attack graph tool allowing automated calculation of attack paths between assets in a cluster
- [Marvin](https://github.com/undistro/marvin) is a CLI tool that scans a k8s cluster by performing CEL expressions to report potential issues, misconfigurations and vulnerabilities.


## Runtime level security

- [sysbox](https://github.com/nestybox/sysbox)


## Dependencies management

- [dependabot](https://github.com/dependabot)
- [renovate](https://github.com/renovatebot/renovate)
- [greenkeeper](https://greenkeeper.io) for npm dependencies
- [doppins](https://doppins.com)
- [tidelift](https://tidelift.com)
- [fossa](https://fossa.com)
- [diun](https://github.com/crazy-max/diun)


## Attack Surface Management

- [detectify](https://detectify.com/product/surface-monitoring)

## Web Application Scanning

- [detectify](https://detectify.com/product/application-scanning)
- [qualys](https://www.qualys.com/apps/web-app-scanning/)

## Infrastructure Security Assessment
- [prowler](https://prowler.pro/)

## Monitoring

- [weave scope](https://www.weave.works/oss/scope/) automatically detects processes, containers, hosts. No kernel modules, no agents, no special libraries, no coding. Seamless integration with Docker, Kubernetes, DCOS and AWS ECS.

## Vulnerabilities

- [metahub](https://github.com/gabrielsoltz/metahub) is an ASFF security context enrichment and command line utility for AWS Security Hub.
