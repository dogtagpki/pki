# Kubernetes Operator Specification

## 3. Kubernetes Operator for PKI Management

### 3.1 Operator Overview

The Dogtag PKI Operator automates deployment, scaling, and lifecycle management of PKI subsystems in Kubernetes.

**Key Features:**
- Declarative PKI instance management
- Automated certificate lifecycle
- Self-healing and auto-scaling
- Backup and restore automation
- HSM integration
- Multi-tenancy support

### 3.2 Custom Resource Definitions (CRDs)

#### 3.2.1 PKIAuthority CRD

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: pkiauthorities.pki.dogtag.org
spec:
  group: pki.dogtag.org
  versions:
  - name: v1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            required:
            - type
            - version
            properties:
              type:
                type: string
                enum: [CA, KRA, OCSP, TKS, TPS, ACME, EST]
                description: "Type of PKI subsystem"

              version:
                type: string
                description: "PKI version (e.g., 11.0.0)"

              replicas:
                type: integer
                minimum: 1
                default: 1
                description: "Number of replicas for HA"

              database:
                type: object
                required:
                - type
                properties:
                  type:
                    type: string
                    enum: [postgresql, ldap, hybrid]
                  connection:
                    type: object
                    properties:
                      host:
                        type: string
                      port:
                        type: integer
                      secretRef:
                        type: object
                        properties:
                          name:
                            type: string

              signing:
                type: object
                properties:
                  algorithm:
                    type: string
                    enum: [RSA, ECDSA, EdDSA]
                    default: RSA
                  keySize:
                    type: integer
                    enum: [2048, 3072, 4096, 8192]
                    default: 4096
                  hsmEnabled:
                    type: boolean
                    default: false
                  hsmConfig:
                    type: object
                    properties:
                      provider:
                        type: string
                        enum: [nCipher, Luna, SoftHSM]
                      secretRef:
                        type: object
                        properties:
                          name:
                            type: string

              security:
                type: object
                properties:
                  authentication:
                    type: array
                    items:
                      type: object
                      properties:
                        type:
                          type: string
                          enum: [client-cert, oauth2, ldap, password]
                        config:
                          type: object
                          x-kubernetes-preserve-unknown-fields: true

                  tls:
                    type: object
                    properties:
                      enabled:
                        type: boolean
                        default: true
                      certificateRef:
                        type: object
                        properties:
                          name:
                            type: string

              persistence:
                type: object
                properties:
                  auditLogs:
                    type: object
                    properties:
                      storage:
                        type: string
                        enum: [filesystem, s3, azure-blob]
                      bucket:
                        type: string
                      retention:
                        type: string
                        pattern: '^\d+[ymd]$'

                  volumeClaim:
                    type: object
                    properties:
                      storageClassName:
                        type: string
                      size:
                        type: string

              monitoring:
                type: object
                properties:
                  metrics:
                    type: boolean
                    default: true
                  tracing:
                    type: boolean
                    default: false
                  servicemonitor:
                    type: boolean
                    default: false

              compliance:
                type: object
                properties:
                  dataResidency:
                    type: string
                    description: "Geographic restriction (e.g., EU, US)"
                  auditLevel:
                    type: string
                    enum: [none, basic, high, maximum]
                    default: high
                  fipsMode:
                    type: boolean
                    default: false

              resources:
                type: object
                properties:
                  requests:
                    type: object
                    properties:
                      cpu:
                        type: string
                      memory:
                        type: string
                  limits:
                    type: object
                    properties:
                      cpu:
                        type: string
                      memory:
                        type: string

          status:
            type: object
            properties:
              phase:
                type: string
                enum: [Pending, Initializing, Ready, Failed, Upgrading]
              conditions:
                type: array
                items:
                  type: object
                  properties:
                    type:
                      type: string
                    status:
                      type: string
                    lastTransitionTime:
                      type: string
                      format: date-time
                    reason:
                      type: string
                    message:
                      type: string
              endpoints:
                type: object
                properties:
                  rest:
                    type: string
                  admin:
                    type: string
              certificateInfo:
                type: object
                properties:
                  signingCert:
                    type: string
                  serialNumber:
                    type: string
                  expiresAt:
                    type: string
                    format: date-time
    subresources:
      status: {}
    additionalPrinterColumns:
    - name: Type
      type: string
      jsonPath: .spec.type
    - name: Status
      type: string
      jsonPath: .status.phase
    - name: Replicas
      type: integer
      jsonPath: .spec.replicas
    - name: Age
      type: date
      jsonPath: .metadata.creationTimestamp
  scope: Namespaced
  names:
    plural: pkiauthorities
    singular: pkiauthority
    kind: PKIAuthority
    shortNames:
    - pki
```

#### 3.2.2 PKIBackup CRD

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: pkibackups.pki.dogtag.org
spec:
  group: pki.dogtag.org
  versions:
  - name: v1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            required:
            - authorityRef
            - destination
            properties:
              authorityRef:
                type: object
                properties:
                  name:
                    type: string

              destination:
                type: object
                properties:
                  type:
                    type: string
                    enum: [s3, azure-blob, gcs, pvc]
                  bucket:
                    type: string
                  secretRef:
                    type: object
                    properties:
                      name:
                        type: string

              schedule:
                type: string
                description: "Cron expression for scheduled backups"

              retention:
                type: object
                properties:
                  keepLast:
                    type: integer
                  keepDays:
                    type: integer

              includeKeys:
                type: boolean
                default: true
                description: "Include private keys in backup"

          status:
            type: object
            properties:
              lastBackupTime:
                type: string
                format: date-time
              lastBackupSize:
                type: string
              phase:
                type: string
                enum: [Pending, Running, Completed, Failed]
  scope: Namespaced
  names:
    plural: pkibackups
    singular: pkibackup
    kind: PKIBackup
```

### 3.3 Operator Implementation

#### 3.3.1 Go Operator Structure (Operator SDK)

```
pki-operator/
├── Dockerfile
├── Makefile
├── go.mod
├── go.sum
├── main.go
├── PROJECT
├── config/
│   ├── crd/
│   │   └── bases/
│   │       ├── pki.dogtag.org_pkiauthorities.yaml
│   │       └── pki.dogtag.org_pkibackups.yaml
│   ├── rbac/
│   ├── manager/
│   └── samples/
└── controllers/
    ├── pkiauthority_controller.go
    ├── pkibackup_controller.go
    └── suite_test.go
```

#### 3.3.2 Main Controller Logic

```go
// controllers/pkiauthority_controller.go
package controllers

import (
    "context"
    "fmt"
    "time"

    appsv1 "k8s.io/api/apps/v1"
    corev1 "k8s.io/api/core/v1"
    "k8s.io/apimachinery/pkg/api/errors"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/runtime"
    "k8s.io/apimachinery/pkg/types"
    ctrl "sigs.k8s.io/controller-runtime"
    "sigs.k8s.io/controller-runtime/pkg/client"
    "sigs.k8s.io/controller-runtime/pkg/log"

    pkiv1 "github.com/dogtagpki/pki-operator/api/v1"
)

type PKIAuthorityReconciler struct {
    client.Client
    Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=pki.dogtag.org,resources=pkiauthorities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pki.dogtag.org,resources=pkiauthorities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch

func (r *PKIAuthorityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    logger := log.FromContext(ctx)
    logger.Info("Reconciling PKIAuthority", "name", req.NamespacedName)

    // Fetch the PKIAuthority instance
    pkiAuthority := &pkiv1.PKIAuthority{}
    err := r.Get(ctx, req.NamespacedName, pkiAuthority)
    if err != nil {
        if errors.IsNotFound(err) {
            logger.Info("PKIAuthority resource not found, ignoring")
            return ctrl.Result{}, nil
        }
        logger.Error(err, "Failed to get PKIAuthority")
        return ctrl.Result{}, err
    }

    // Update status to Initializing
    if pkiAuthority.Status.Phase == "" {
        pkiAuthority.Status.Phase = pkiv1.PhaseInitializing
        if err := r.Status().Update(ctx, pkiAuthority); err != nil {
            logger.Error(err, "Failed to update PKIAuthority status")
            return ctrl.Result{}, err
        }
    }

    // Reconcile Database
    if err := r.reconcileDatabase(ctx, pkiAuthority); err != nil {
        return r.updateStatusFailed(ctx, pkiAuthority, err)
    }

    // Reconcile ConfigMap
    if err := r.reconcileConfigMap(ctx, pkiAuthority); err != nil {
        return r.updateStatusFailed(ctx, pkiAuthority, err)
    }

    // Reconcile Deployment
    if err := r.reconcileDeployment(ctx, pkiAuthority); err != nil {
        return r.updateStatusFailed(ctx, pkiAuthority, err)
    }

    // Reconcile Service
    if err := r.reconcileService(ctx, pkiAuthority); err != nil {
        return r.updateStatusFailed(ctx, pkiAuthority, err)
    }

    // Check if deployment is ready
    deployment := &appsv1.Deployment{}
    err = r.Get(ctx, types.NamespacedName{
        Name:      pkiAuthority.Name,
        Namespace: pkiAuthority.Namespace,
    }, deployment)
    if err != nil {
        return ctrl.Result{}, err
    }

    if deployment.Status.ReadyReplicas == *deployment.Spec.Replicas {
        // Update status to Ready
        pkiAuthority.Status.Phase = pkiv1.PhaseReady
        pkiAuthority.Status.Endpoints = pkiv1.Endpoints{
            REST:  fmt.Sprintf("https://%s.%s.svc.cluster.local", pkiAuthority.Name, pkiAuthority.Namespace),
            Admin: fmt.Sprintf("https://%s-admin.%s.svc.cluster.local", pkiAuthority.Name, pkiAuthority.Namespace),
        }

        if err := r.Status().Update(ctx, pkiAuthority); err != nil {
            logger.Error(err, "Failed to update PKIAuthority status to Ready")
            return ctrl.Result{}, err
        }

        logger.Info("PKIAuthority is ready", "name", pkiAuthority.Name)
    }

    return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *PKIAuthorityReconciler) reconcileDatabase(ctx context.Context, pki *pkiv1.PKIAuthority) error {
    logger := log.FromContext(ctx)

    switch pki.Spec.Database.Type {
    case "postgresql":
        return r.ensurePostgreSQLDatabase(ctx, pki)
    case "ldap":
        return r.ensureLDAPDatabase(ctx, pki)
    case "hybrid":
        if err := r.ensurePostgreSQLDatabase(ctx, pki); err != nil {
            return err
        }
        return r.ensureLDAPDatabase(ctx, pki)
    default:
        return fmt.Errorf("unsupported database type: %s", pki.Spec.Database.Type)
    }
}

func (r *PKIAuthorityReconciler) ensurePostgreSQLDatabase(ctx context.Context, pki *pkiv1.PKIAuthority) error {
    // Create PostgreSQL database if needed
    // This could be a separate StatefulSet or external database
    return nil
}

func (r *PKIAuthorityReconciler) reconcileConfigMap(ctx context.Context, pki *pkiv1.PKIAuthority) error {
    configMap := &corev1.ConfigMap{
        ObjectMeta: metav1.ObjectMeta{
            Name:      fmt.Sprintf("%s-config", pki.Name),
            Namespace: pki.Namespace,
        },
        Data: map[string]string{
            "application.properties": r.generateConfig(pki),
        },
    }

    // Set PKIAuthority instance as the owner
    ctrl.SetControllerReference(pki, configMap, r.Scheme)

    found := &corev1.ConfigMap{}
    err := r.Get(ctx, types.NamespacedName{
        Name:      configMap.Name,
        Namespace: configMap.Namespace,
    }, found)

    if err != nil && errors.IsNotFound(err) {
        return r.Create(ctx, configMap)
    } else if err != nil {
        return err
    }

    // Update existing ConfigMap
    found.Data = configMap.Data
    return r.Update(ctx, found)
}

func (r *PKIAuthorityReconciler) reconcileDeployment(ctx context.Context, pki *pkiv1.PKIAuthority) error {
    labels := map[string]string{
        "app":  pki.Name,
        "type": string(pki.Spec.Type),
    }

    replicas := pki.Spec.Replicas
    if replicas == 0 {
        replicas = 1
    }

    deployment := &appsv1.Deployment{
        ObjectMeta: metav1.ObjectMeta{
            Name:      pki.Name,
            Namespace: pki.Namespace,
        },
        Spec: appsv1.DeploymentSpec{
            Replicas: &replicas,
            Selector: &metav1.LabelSelector{
                MatchLabels: labels,
            },
            Template: corev1.PodTemplateSpec{
                ObjectMeta: metav1.ObjectMeta{
                    Labels: labels,
                },
                Spec: corev1.PodSpec{
                    Containers: []corev1.Container{
                        {
                            Name:  string(pki.Spec.Type),
                            Image: fmt.Sprintf("dogtagpki/%s-service:%s",
                                string(pki.Spec.Type), pki.Spec.Version),
                            Ports: []corev1.ContainerPort{
                                {
                                    ContainerPort: 8443,
                                    Name:          "https",
                                },
                            },
                            Env: r.buildEnvVars(pki),
                            VolumeMounts: []corev1.VolumeMount{
                                {
                                    Name:      "config",
                                    MountPath: "/config",
                                },
                            },
                            Resources: *pki.Spec.Resources,
                        },
                    },
                    Volumes: []corev1.Volume{
                        {
                            Name: "config",
                            VolumeSource: corev1.VolumeSource{
                                ConfigMap: &corev1.ConfigMapVolumeSource{
                                    LocalObjectReference: corev1.LocalObjectReference{
                                        Name: fmt.Sprintf("%s-config", pki.Name),
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }

    ctrl.SetControllerReference(pki, deployment, r.Scheme)

    found := &appsv1.Deployment{}
    err := r.Get(ctx, types.NamespacedName{
        Name:      deployment.Name,
        Namespace: deployment.Namespace,
    }, found)

    if err != nil && errors.IsNotFound(err) {
        return r.Create(ctx, deployment)
    } else if err != nil {
        return err
    }

    // Update existing Deployment
    found.Spec = deployment.Spec
    return r.Update(ctx, found)
}

func (r *PKIAuthorityReconciler) reconcileService(ctx context.Context, pki *pkiv1.PKIAuthority) error {
    service := &corev1.Service{
        ObjectMeta: metav1.ObjectMeta{
            Name:      pki.Name,
            Namespace: pki.Namespace,
        },
        Spec: corev1.ServiceSpec{
            Selector: map[string]string{
                "app": pki.Name,
            },
            Ports: []corev1.ServicePort{
                {
                    Port:     443,
                    TargetPort: intstr.FromInt(8443),
                    Name:     "https",
                },
            },
            Type: corev1.ServiceTypeClusterIP,
        },
    }

    ctrl.SetControllerReference(pki, service, r.Scheme)

    found := &corev1.Service{}
    err := r.Get(ctx, types.NamespacedName{
        Name:      service.Name,
        Namespace: service.Namespace,
    }, found)

    if err != nil && errors.IsNotFound(err) {
        return r.Create(ctx, service)
    } else if err != nil {
        return err
    }

    return nil
}

func (r *PKIAuthorityReconciler) buildEnvVars(pki *pkiv1.PKIAuthority) []corev1.EnvVar {
    envVars := []corev1.EnvVar{
        {
            Name:  "PKI_TYPE",
            Value: string(pki.Spec.Type),
        },
        {
            Name:  "DB_TYPE",
            Value: pki.Spec.Database.Type,
        },
    }

    if pki.Spec.Database.Connection.SecretRef.Name != "" {
        envVars = append(envVars, []corev1.EnvVar{
            {
                Name: "DB_USER",
                ValueFrom: &corev1.EnvVarSource{
                    SecretKeyRef: &corev1.SecretKeySelector{
                        LocalObjectReference: corev1.LocalObjectReference{
                            Name: pki.Spec.Database.Connection.SecretRef.Name,
                        },
                        Key: "username",
                    },
                },
            },
            {
                Name: "DB_PASSWORD",
                ValueFrom: &corev1.EnvVarSource{
                    SecretKeyRef: &corev1.SecretKeySelector{
                        LocalObjectReference: corev1.LocalObjectReference{
                            Name: pki.Spec.Database.Connection.SecretRef.Name,
                        },
                        Key: "password",
                    },
                },
            },
        }...)
    }

    return envVars
}

func (r *PKIAuthorityReconciler) generateConfig(pki *pkiv1.PKIAuthority) string {
    // Generate application.properties based on spec
    return fmt.Sprintf(`
quarkus.application.name=%s-service
quarkus.datasource.db-kind=%s
quarkus.micrometer.enabled=%t
`, pki.Name, pki.Spec.Database.Type, pki.Spec.Monitoring.Metrics)
}

func (r *PKIAuthorityReconciler) updateStatusFailed(ctx context.Context, pki *pkiv1.PKIAuthority, err error) (ctrl.Result, error) {
    pki.Status.Phase = pkiv1.PhaseFailed
    if statusErr := r.Status().Update(ctx, pki); statusErr != nil {
        return ctrl.Result{}, statusErr
    }
    return ctrl.Result{}, err
}

func (r *PKIAuthorityReconciler) SetupWithManager(mgr ctrl.Manager) error {
    return ctrl.NewControllerManagedBy(mgr).
        For(&pkiv1.PKIAuthority{}).
        Owns(&appsv1.Deployment{}).
        Owns(&corev1.Service{}).
        Owns(&corev1.ConfigMap{}).
        Complete(r)
}
```

### 3.4 Example Custom Resources

#### 3.4.1 Production CA Authority

```yaml
apiVersion: pki.dogtag.org/v1
kind: PKIAuthority
metadata:
  name: production-ca
  namespace: pki-prod
spec:
  type: CA
  version: "11.0.0"
  replicas: 3

  database:
    type: postgresql
    connection:
      host: postgres-ha.database.svc.cluster.local
      port: 5432
      secretRef:
        name: ca-db-credentials

  signing:
    algorithm: RSA
    keySize: 4096
    hsmEnabled: true
    hsmConfig:
      provider: Luna
      secretRef:
        name: hsm-credentials

  security:
    authentication:
    - type: client-cert
    - type: oauth2
      config:
        issuer: https://idp.example.com
        clientId: pki-ca
    tls:
      enabled: true
      certificateRef:
        name: ca-tls-cert

  persistence:
    auditLogs:
      storage: s3
      bucket: pki-audit-logs-prod
      retention: 7y
    volumeClaim:
      storageClassName: fast-ssd
      size: 100Gi

  monitoring:
    metrics: true
    tracing: true
    serviceMonitor: true

  compliance:
    dataResidency: EU
    auditLevel: maximum
    fipsMode: true

  resources:
    requests:
      cpu: "1"
      memory: "2Gi"
    limits:
      cpu: "2"
      memory: "4Gi"
```

#### 3.4.2 ACME Service

```yaml
apiVersion: pki.dogtag.org/v1
kind: PKIAuthority
metadata:
  name: acme-letsencrypt
  namespace: pki-prod
spec:
  type: ACME
  version: "11.0.0"
  replicas: 5

  database:
    type: postgresql
    connection:
      secretRef:
        name: acme-db-credentials

  security:
    tls:
      enabled: true
      certificateRef:
        name: acme-tls-cert

  monitoring:
    metrics: true
    serviceMonitor: true

  resources:
    requests:
      cpu: "500m"
      memory: "512Mi"
    limits:
      cpu: "1"
      memory: "1Gi"
```

#### 3.4.3 Backup Schedule

```yaml
apiVersion: pki.dogtag.org/v1
kind: PKIBackup
metadata:
  name: daily-ca-backup
  namespace: pki-prod
spec:
  authorityRef:
    name: production-ca

  destination:
    type: s3
    bucket: pki-backups
    secretRef:
      name: s3-credentials

  schedule: "0 2 * * *"  # Daily at 2 AM

  retention:
    keepLast: 30
    keepDays: 365

  includeKeys: true
```

### 3.5 Operator Deployment

#### 3.5.1 Install CRDs

```bash
make install
```

#### 3.5.2 Deploy Operator

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pki-operator
  namespace: pki-system
spec:
  replicas: 1
  selector:
    matchLabels:
      control-plane: pki-operator
  template:
    metadata:
      labels:
        control-plane: pki-operator
    spec:
      serviceAccountName: pki-operator
      containers:
      - name: manager
        image: dogtagpki/pki-operator:11.0.0
        command:
        - /manager
        args:
        - --leader-elect
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
          requests:
            cpu: 100m
            memory: 128Mi
```

### 3.6 Benefits

1. **Declarative Management:** Infrastructure as Code
2. **Self-Healing:** Automatic recovery from failures
3. **Simplified Operations:** No manual deployment scripts
4. **Version Control:** GitOps-ready configuration
5. **Multi-Tenancy:** Multiple PKI instances in one cluster
6. **Automated Lifecycle:** Upgrades, backups, scaling
