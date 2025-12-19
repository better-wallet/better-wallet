# Kubernetes Deployment

This guide covers deploying Better Wallet on Kubernetes for production environments with high availability and scalability.

## Prerequisites

- Kubernetes 1.28+
- kubectl configured
- Helm 3.0+ (optional)
- PostgreSQL database (managed or self-hosted)
- KMS access (AWS KMS, Vault, etc.)

## Quick Start with Helm

```bash
# Add the Better Wallet Helm repository
helm repo add better-wallet https://charts.better-wallet.com
helm repo update

# Install with default configuration
helm install better-wallet better-wallet/better-wallet \
  --namespace better-wallet \
  --create-namespace \
  --set postgresql.enabled=true \
  --set kms.provider=local \
  --set kms.localMasterKey="dev-master-key-12345678901234567890123456789012"

# Verify installation
kubectl -n better-wallet get pods
```

## Manual Kubernetes Deployment

### Namespace and Secrets

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: better-wallet
  labels:
    name: better-wallet
---
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: better-wallet-secrets
  namespace: better-wallet
type: Opaque
stringData:
  POSTGRES_DSN: "postgres://user:password@postgres:5432/better_wallet?sslmode=require"
  KMS_AWS_KEY_ID: "arn:aws:kms:us-east-1:123456789:key/abc-def-123"
```

Apply secrets:

```bash
kubectl apply -f namespace.yaml
kubectl apply -f secrets.yaml
```

### ConfigMap

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: better-wallet-config
  namespace: better-wallet
data:
  PORT: "8080"
  EXECUTION_BACKEND: "kms"
  KMS_PROVIDER: "aws-kms"
  KMS_AWS_REGION: "us-east-1"
  LOG_LEVEL: "info"
```

### Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: better-wallet
  namespace: better-wallet
  labels:
    app: better-wallet
spec:
  replicas: 3
  selector:
    matchLabels:
      app: better-wallet
  template:
    metadata:
      labels:
        app: better-wallet
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: better-wallet
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: better-wallet
          image: ghcr.io/better-wallet/better-wallet:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 8080
              name: http
              protocol: TCP
          envFrom:
            - configMapRef:
                name: better-wallet-config
            - secretRef:
                name: better-wallet-secrets
          resources:
            requests:
              cpu: "500m"
              memory: "512Mi"
            limits:
              cpu: "2000m"
              memory: "2Gi"
          livenessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 15
            periodSeconds: 20
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app: better-wallet
                topologyKey: kubernetes.io/hostname
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              app: better-wallet
```

### Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: better-wallet
  namespace: better-wallet
  labels:
    app: better-wallet
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: http
      protocol: TCP
      name: http
  selector:
    app: better-wallet
```

### Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: better-wallet
  namespace: better-wallet
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - wallet.example.com
      secretName: better-wallet-tls
  rules:
    - host: wallet.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: better-wallet
                port:
                  number: 80
```

### ServiceAccount and RBAC

```yaml
# rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: better-wallet
  namespace: better-wallet
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: better-wallet
  namespace: better-wallet
rules:
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: better-wallet
  namespace: better-wallet
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: better-wallet
subjects:
  - kind: ServiceAccount
    name: better-wallet
    namespace: better-wallet
```

### HorizontalPodAutoscaler

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: better-wallet
  namespace: better-wallet
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: better-wallet
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
```

### PodDisruptionBudget

```yaml
# pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: better-wallet
  namespace: better-wallet
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: better-wallet
```

## Apply All Resources

```bash
kubectl apply -f namespace.yaml
kubectl apply -f secrets.yaml
kubectl apply -f configmap.yaml
kubectl apply -f rbac.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
kubectl apply -f hpa.yaml
kubectl apply -f pdb.yaml
```

## AWS Integration

### IAM Role for Service Account (IRSA)

```yaml
# serviceaccount-irsa.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: better-wallet
  namespace: better-wallet
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789:role/better-wallet-kms-role
```

Create the IAM role:

```bash
# Create IAM policy
cat > kms-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:123456789:key/abc-def-123"
    }
  ]
}
EOF

aws iam create-policy \
  --policy-name BetterWalletKMSPolicy \
  --policy-document file://kms-policy.json

# Create IAM role with trust policy for EKS
eksctl create iamserviceaccount \
  --name better-wallet \
  --namespace better-wallet \
  --cluster my-cluster \
  --attach-policy-arn arn:aws:iam::123456789:policy/BetterWalletKMSPolicy \
  --approve
```

## PostgreSQL on Kubernetes

### Using CloudNativePG

```yaml
# postgresql.yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: better-wallet-db
  namespace: better-wallet
spec:
  instances: 3
  primaryUpdateStrategy: unsupervised
  storage:
    size: 100Gi
    storageClass: gp3
  postgresql:
    parameters:
      max_connections: "200"
      shared_buffers: "256MB"
  bootstrap:
    initdb:
      database: better_wallet
      owner: bw_user
      secret:
        name: better-wallet-db-credentials
  backup:
    barmanObjectStore:
      destinationPath: s3://my-bucket/postgresql
      s3Credentials:
        accessKeyId:
          name: aws-creds
          key: ACCESS_KEY_ID
        secretAccessKey:
          name: aws-creds
          key: SECRET_ACCESS_KEY
    retentionPolicy: "30d"
```

## Monitoring

### ServiceMonitor for Prometheus

```yaml
# servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: better-wallet
  namespace: better-wallet
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app: better-wallet
  endpoints:
    - port: http
      path: /metrics
      interval: 15s
```

### Grafana Dashboard

Import the Better Wallet Grafana dashboard:

```bash
# Get dashboard JSON
curl -o dashboard.json https://raw.githubusercontent.com/better-wallet/better-wallet/main/deploy/grafana/dashboard.json

# Import via Grafana API
curl -X POST \
  -H "Content-Type: application/json" \
  -d @dashboard.json \
  http://admin:admin@grafana:3000/api/dashboards/db
```

## Network Policies

```yaml
# networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: better-wallet
  namespace: better-wallet
spec:
  podSelector:
    matchLabels:
      app: better-wallet
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
  egress:
    # PostgreSQL
    - to:
        - podSelector:
            matchLabels:
              app: postgresql
      ports:
        - protocol: TCP
          port: 5432
    # DNS
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
    # AWS endpoints (KMS, STS)
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 443
```

## Rolling Updates

```bash
# Update image
kubectl -n better-wallet set image deployment/better-wallet \
  better-wallet=ghcr.io/better-wallet/better-wallet:v1.2.0

# Watch rollout
kubectl -n better-wallet rollout status deployment/better-wallet

# Rollback if needed
kubectl -n better-wallet rollout undo deployment/better-wallet
```

## Troubleshooting

### Pod Issues

```bash
# Check pod status
kubectl -n better-wallet get pods

# Describe pod for events
kubectl -n better-wallet describe pod <pod-name>

# View logs
kubectl -n better-wallet logs -f deployment/better-wallet

# Exec into pod
kubectl -n better-wallet exec -it <pod-name> -- sh
```

### Network Issues

```bash
# Test service connectivity
kubectl -n better-wallet run debug --rm -it --image=busybox -- wget -qO- http://better-wallet/health

# Check endpoints
kubectl -n better-wallet get endpoints better-wallet
```

### Database Connectivity

```bash
# Test database connection from pod
kubectl -n better-wallet exec -it <pod-name> -- sh -c 'nc -z postgres 5432 && echo "OK"'
```

## Helm Values Reference

```yaml
# values.yaml
replicaCount: 3

image:
  repository: ghcr.io/better-wallet/better-wallet
  tag: latest
  pullPolicy: Always

service:
  type: ClusterIP
  port: 80

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: wallet.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: better-wallet-tls
      hosts:
        - wallet.example.com

resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 2Gi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

postgresql:
  enabled: true
  auth:
    database: better_wallet
    username: bw_user
    existingSecret: better-wallet-db-credentials

kms:
  provider: aws-kms
  awsKeyId: ""
  awsRegion: us-east-1

env:
  LOG_LEVEL: info
```

## Next Steps

- [Environment Variables](./environment-variables.md) - Configuration reference
- [Monitoring](./monitoring.md) - Metrics and alerting
- [TLS Configuration](./tls-configuration.md) - HTTPS setup
- [Backup & Recovery](./backup-recovery.md) - Data protection
