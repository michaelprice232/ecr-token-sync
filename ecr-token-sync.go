// Script which retrieves an AWS ECR auth token and then writes it as an image pull secret to every namespace in the k8s cluster.
// It also updates the default service account in each namespace so that pods with no service account implicitly get the image pull permissions.
// Designed to be deployed within a cluster not running on AWS EC2 workers, for which pods can't pull transparently from ECR.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const (
	defaultRegion = "eu-west-2"
	secretName    = "ecr-pull-creds"
)

// ecrToken stores the auth token details in the Config struct.
type ecrToken struct {
	username     string
	token        string
	encodedToken string
}

// Config holds the clients and any required variables in the program.
type Config struct {
	k8sClient  *kubernetes.Clientset
	ecrClient  *ecr.Client
	logger     *slog.Logger
	awsAccount string
	region     string
	token      *ecrToken
}

// getAccountID retrieves the AWS account ID based on the credentials being used.
func getAccountID(cfg aws.Config) (string, error) {
	stsClient := sts.NewFromConfig(cfg)

	res, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("error getting account ID: %v", err)
	}

	return *res.Account, nil
}

// newConfig returns Config by reading env vars and initialising clients.
func newConfig() (*Config, error) {
	var c Config

	// Default to eu-west-2 region
	var region = os.Getenv("AWS_REGION")
	if region == "" {
		region = defaultRegion
	}

	// Create structured logger and default to error level (https://pkg.go.dev/log/slog#Level)
	var logLevel = os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "8"
	}
	level, err := strconv.Atoi(logLevel)
	if err != nil {
		return nil, fmt.Errorf("error parsing LOG_LEVEL: %v", err)
	}
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.Level(level)})
	logger := slog.New(handler)

	// Expects AWS credentials to be available as env vars or shared profile
	awsCfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return &c, fmt.Errorf("unable to load AWS SDK config, %v", err)
	}
	ecrClient := ecr.NewFromConfig(awsCfg)

	// Get account ID
	accountId, err := getAccountID(awsCfg)
	if err != nil {
		return &c, fmt.Errorf("error getting account ID: %v", err)
	}

	// Load k8s config from kubeconfig file if running locally, or else in-cluster config
	var runningLocally = os.Getenv("RUNNING_LOCALLY")
	var k8sCfg *rest.Config
	if runningLocally == "true" {
		logger.Info("RUNNING_LOCALLY envar has been detected. Using local kubeconfig file")
		k8sCfg, err = clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
		if err != nil {
			return &c, fmt.Errorf("unable to build K8s local config, %v", err)
		}
	} else {
		k8sCfg, err = rest.InClusterConfig()
		if err != nil {
			return &c, fmt.Errorf("unable to load in-cluster config, %v", err)
		}
	}
	k8sClientSet, err := kubernetes.NewForConfig(k8sCfg)
	if err != nil {
		return &c, fmt.Errorf("unable to build K8s client set, %v", err)
	}

	c = Config{
		k8sClient:  k8sClientSet,
		ecrClient:  ecrClient,
		logger:     logger,
		awsAccount: accountId,
		region:     region,
	}

	return &c, nil
}

// getToken populates the Config with an ecrToken.
func (c *Config) getToken() error {
	var t ecrToken

	// Get an auth token from AWS ECR which is valid for 12 hours
	res, err := c.ecrClient.GetAuthorizationToken(context.TODO(), &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return fmt.Errorf("unable to get ECR authorization token, %v", err)
	}

	// Result is base64 encoded. Pull out the config
	encodedToken := res.AuthorizationData[0].AuthorizationToken
	decodedToken, err := base64.StdEncoding.DecodeString(*encodedToken)
	if err != nil {
		return fmt.Errorf("unable to base64 decode the authorization token, %v", err)
	}
	username := strings.Split(string(decodedToken), ":")[0]
	token := strings.Split(string(decodedToken), ":")[1]

	t = ecrToken{
		username:     username,
		token:        token,
		encodedToken: *encodedToken,
	}

	c.token = &t

	return nil
}

// dockerConfig holds the authentication details which will be embedded in the image pull secret.
type dockerConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Auth     string `json:"auth"`
}

// getDockerConfig returns the config as a JSON string, appropriate for creating a Docker image pull K8s secret.
func (c *Config) getDockerConfig() (string, error) {
	// Build the format required by Docker image pull credential secrets
	// https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/#registry-secret-existing-credentials
	var payload = struct {
		Auths map[string]dockerConfig
	}{
		Auths: map[string]dockerConfig{
			fmt.Sprintf("https://%s.dkr.ecr.%s.amazonaws.com", c.awsAccount, c.region): {
				Username: c.token.username,
				Password: c.token.token,
				Email:    "noreply@email.com",
				Auth:     c.token.encodedToken,
			},
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("unable to marshal JSON payload, %v", err)
	}

	return string(jsonPayload), nil
}

// deploySecretToNamespace either creates or updates a secret in a namespace depending on whether it already exists.
func (c *Config) deploySecretToNamespace(namespace string, secret coreV1.Secret) error {
	// Check if we need to create a new secret or update an existing one
	createSecret := false
	_, err := c.k8sClient.CoreV1().Secrets(namespace).Get(context.TODO(), secret.Name, metav1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		createSecret = true
	}
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("unable to check if secret is present in namespace %s: %v", secret.Namespace, err)
	}

	if createSecret {
		_, err = c.k8sClient.CoreV1().Secrets(namespace).Create(context.TODO(), &secret, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create secret %s in namespace %s: %v", secret.Name, namespace, err)
		}
		c.logger.Info("Secret created in namespace", "name", secret.Name, "namespace", secret.Namespace)
		return nil
	}

	_, err = c.k8sClient.CoreV1().Secrets(namespace).Update(context.TODO(), &secret, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("unable to update secret %s in namespace %s: %v", secret.Name, namespace, err)
	}

	c.logger.Info("Secret updated in namespace", "name", secret.Name, "namespace", secret.Namespace)

	return nil
}

func containsObjectRef(slice []coreV1.LocalObjectReference, secretName string) bool {
	for _, item := range slice {
		if item.Name == secretName {
			return true
		}
	}
	return false
}

// updateDefaultServiceAccount patches the default service account with the Docker image pull secret.
// The service account is guaranteed to be present by the control plane.
func (c *Config) updateDefaultServiceAccount(namespace string) error {
	serviceAccountName := "default"

	sa, err := c.k8sClient.CoreV1().ServiceAccounts(namespace).Get(context.TODO(), serviceAccountName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get service account %s in namespace %s: %v", serviceAccountName, namespace, err)
	}

	// Only update if not already present
	if !containsObjectRef(sa.ImagePullSecrets, secretName) {
		c.logger.Info("Patching service account with image pull secret", "namespace", namespace, "serviceAccountName", serviceAccountName, "imagePullSecret", secretName)

		ref := coreV1.LocalObjectReference{Name: secretName}
		sa.ImagePullSecrets = append(sa.ImagePullSecrets, ref)

		_, err = c.k8sClient.CoreV1().ServiceAccounts(namespace).Update(context.TODO(), sa, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("unable to update service account %s in namespace %s: %v", serviceAccountName, namespace, err)
		}
	}

	return nil
}

func main() {
	cfg, err := newConfig()
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	err = cfg.getToken()
	if err != nil {
		cfg.logger.Error("getting token", slog.Any("err", err))
		os.Exit(1)
	}

	encodedPayload, err := cfg.getDockerConfig()
	if err != nil {
		cfg.logger.Error("getting docker config", slog.Any("err", err))
		os.Exit(2)
	}

	namespaces, err := cfg.k8sClient.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		cfg.logger.Error("unable to list namespaces", slog.Any("err", err))
		os.Exit(3)
	}

	for _, n := range namespaces.Items {
		namespace := n.ObjectMeta.Name

		secret := coreV1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Labels:    map[string]string{"managed-by": "ecr-token-sync"},
			},

			// Required format for Docker compatible registry logins
			StringData: map[string]string{
				".dockerconfigjson": encodedPayload,
			},

			Type: "kubernetes.io/dockerconfigjson",
		}

		// Create/update image pull secret
		err = cfg.deploySecretToNamespace(namespace, secret)
		if err != nil {
			cfg.logger.Error("unable to deploy secret to namespace", slog.Any("err", err))
		}

		// Ensure the default service account references the image pull secret
		err = cfg.updateDefaultServiceAccount(namespace)
		if err != nil {
			cfg.logger.Error("unable to update default service account", slog.Any("err", err))
		}
	}
}
