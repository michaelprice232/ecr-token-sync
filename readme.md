# ecr-token-sync

Script which creates Docker [image pull secrets](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/) in all namespaces in the cluster based on an AWS ECR auth token.
It also updates the default service account in each namespace so that pods with no service account implicitly get the image pull permissions.
Designed to be deployed as a CronJob in K8s clusters which are not running on AWS EC2 workers and so can't pull ECR images transparently.
ECR tokens are only valid for 12 hours by design hence the requirement for a reoccurring job.

## Running locally

```shell
export AWS_PROFILE="<profile>"    # set the profile to the AWS account you want to generate the AWS ECR token from
export RUNNING_LOCALLY=true       # uses the local kubeconfig context (instead of in-cluster config)
export LOG_LEVEL=0                # optional - sets log level to info. Defaults to error - https://pkg.go.dev/log/slog#Level

kubectx "<context>"               # set the context to the K8s cluster you want to create the secrets in

go run ecr-token-sync.go
```

## Deploying to cluster

Example CronJob:
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ecr-token-sync
  namespace: ecr-token-sync
spec:
  # Run every 6 hours (ECR auth token expires after 12 hours)
  schedule: "0 */6 * * *"
  successfulJobsHistoryLimit: 3
  suspend: false
  jobTemplate:
    spec:
      backoffLimit: 5
      template:
        spec:
          restartPolicy: OnFailure
          serviceAccountName: ecr-token-sync
          containers:
            - name: main
              image: registry/ecr-token-sync:v1
              imagePullPolicy: IfNotPresent

              # Expects IAM user access keys exported as env vars. Typically sync'd via a Secrets Operator 
              env:
                - name: AWS_ACCESS_KEY_ID
                  valueFrom:
                    secretKeyRef:
                      name: ecr-token-sync-creds
                      key: AWS_ACCESS_KEY_ID
                - name: AWS_SECRET_ACCESS_KEY
                  valueFrom:
                    secretKeyRef:
                      name: ecr-token-sync-creds
                      key: AWS_SECRET_ACCESS_KEY
```