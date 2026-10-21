package multicloud

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/smford/iam-shrink/internal/render"
	"gopkg.in/yaml.v3"
)

// MapAWSToGCP translates AWS IAM actions to equivalent Google Cloud IAM permissions.
func MapAWSToGCP(awsAction string) string {
	parts := strings.SplitN(awsAction, ":", 2)
	if len(parts) != 2 {
		return "custom.permissions.access"
	}
	svc := strings.ToLower(parts[0])
	api := strings.ToLower(parts[1])

	switch svc {
	case "s3":
		if strings.Contains(api, "list") {
			return "storage.objects.list"
		}
		if strings.Contains(api, "get") {
			return "storage.objects.get"
		}
		if strings.Contains(api, "put") || strings.Contains(api, "create") {
			return "storage.objects.create"
		}
		if strings.Contains(api, "delete") {
			return "storage.objects.delete"
		}
		return "storage.objects.get"
	case "dynamodb":
		if strings.Contains(api, "get") || strings.Contains(api, "query") || strings.Contains(api, "scan") {
			return "spanner.databases.read"
		}
		return "spanner.databases.write"
	case "kms":
		if strings.Contains(api, "decrypt") {
			return "cloudkms.cryptoKeyVersions.useToDecrypt"
		}
		if strings.Contains(api, "encrypt") {
			return "cloudkms.cryptoKeyVersions.useToEncrypt"
		}
		return "cloudkms.cryptoKeys.get"
	case "secretsmanager":
		return "secretmanager.versions.access"
	case "sqs", "sns":
		if strings.Contains(api, "publish") || strings.Contains(api, "send") {
			return "pubsub.messages.publish"
		}
		return "pubsub.subscriptions.consume"
	case "lambda":
		return "cloudfunctions.functions.invoke"
	default:
		return fmt.Sprintf("custom.%s.%s", svc, api)
	}
}

// MapAWSToAzure translates AWS IAM actions to equivalent Azure RBAC permissions.
func MapAWSToAzure(awsAction string) string {
	parts := strings.SplitN(awsAction, ":", 2)
	if len(parts) != 2 {
		return "Microsoft.Resources/subscriptions/resourceGroups/read"
	}
	svc := strings.ToLower(parts[0])
	api := strings.ToLower(parts[1])

	switch svc {
	case "s3":
		if strings.Contains(api, "get") || strings.Contains(api, "list") {
			return "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
		}
		if strings.Contains(api, "put") || strings.Contains(api, "create") {
			return "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
		}
		if strings.Contains(api, "delete") {
			return "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
		}
		return "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
	case "dynamodb":
		return "Microsoft.DocumentDB/databaseAccounts/read"
	case "kms":
		if strings.Contains(api, "decrypt") {
			return "Microsoft.KeyVault/vaults/keys/decrypt/action"
		}
		return "Microsoft.KeyVault/vaults/keys/encrypt/action"
	case "secretsmanager":
		return "Microsoft.KeyVault/vaults/secrets/getSecret/action"
	case "sqs", "sns":
		return "Microsoft.ServiceBus/namespaces/queues/messages/send/action"
	default:
		return fmt.Sprintf("Microsoft.Custom/%s/%s/action", svc, api)
	}
}

// RenderGCPIAMCustomRole outputs a GCP Custom Role in YAML.
func RenderGCPIAMCustomRole(items []render.ActionItem) (string, error) {
	seen := make(map[string]bool)
	var perms []string

	for _, it := range items {
		gcpPerm := MapAWSToGCP(it.Action)
		if !seen[gcpPerm] {
			seen[gcpPerm] = true
			perms = append(perms, gcpPerm)
		}
	}
	sort.Strings(perms)

	type gcpRole struct {
		Title               string   `yaml:"title"`
		Description         string   `yaml:"description"`
		Stage               string   `yaml:"stage"`
		IncludedPermissions []string `yaml:"includedPermissions"`
	}

	role := gcpRole{
		Title:               "iam_shrink_least_privilege_role",
		Description:         "Least-privilege role synthesized by iam-shrink",
		Stage:               "GA",
		IncludedPermissions: perms,
	}

	data, err := yaml.Marshal(&role)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// RenderAzureRBAC outputs an Azure Custom Role Definition JSON.
func RenderAzureRBAC(items []render.ActionItem) (string, error) {
	seen := make(map[string]bool)
	var actions []string

	for _, it := range items {
		azAct := MapAWSToAzure(it.Action)
		if !seen[azAct] {
			seen[azAct] = true
			actions = append(actions, azAct)
		}
	}
	sort.Strings(actions)

	type azureRole struct {
		Name             string   `json:"Name"`
		IsCustom         bool     `json:"IsCustom"`
		Description      string   `json:"Description"`
		Actions          []string `json:"Actions"`
		NotActions       []string `json:"NotActions"`
		AssignableScopes []string `json:"AssignableScopes"`
	}

	role := azureRole{
		Name:             "iam-shrink-least-privilege",
		IsCustom:         true,
		Description:      "Least-privilege role synthesized by iam-shrink",
		Actions:          actions,
		NotActions:       []string{},
		AssignableScopes: []string{"/subscriptions/${var.subscription_id}"},
	}

	data, err := json.MarshalIndent(role, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

// RenderK8sRBAC outputs a Kubernetes RBAC Role manifest.
func RenderK8sRBAC(items []render.ActionItem) string {
	var buf bytes.Buffer
	buf.WriteString("apiVersion: rbac.authorization.k8s.io/v1\n")
	buf.WriteString("kind: Role\n")
	buf.WriteString("metadata:\n")
	buf.WriteString("  name: iam-shrink-least-privilege\n")
	buf.WriteString("  namespace: default\n")
	buf.WriteString("rules:\n")

	groups := make(map[string][]string)
	for _, it := range items {
		svc := strings.ToLower(it.Service)
		verb := "get"
		if strings.Contains(strings.ToLower(it.Action), "list") {
			verb = "list"
		} else if strings.Contains(strings.ToLower(it.Action), "put") || strings.Contains(strings.ToLower(it.Action), "create") {
			verb = "create"
		} else if strings.Contains(strings.ToLower(it.Action), "delete") {
			verb = "delete"
		}
		groups[svc] = append(groups[svc], verb)
	}

	for svc, verbs := range groups {
		vSet := make(map[string]bool)
		var vList []string
		for _, v := range verbs {
			if !vSet[v] {
				vSet[v] = true
				vList = append(vList, v)
			}
		}
		sort.Strings(vList)

		buf.WriteString("  - apiGroups: [\"\"]\n")
		buf.WriteString(fmt.Sprintf("    resources: [%q]\n", svc))
		buf.WriteString("    verbs:\n")
		for _, v := range vList {
			buf.WriteString(fmt.Sprintf("      - %q\n", v))
		}
	}

	return buf.String()
}

// RenderVaultSecretRole outputs a HashiCorp Vault dynamic AWS secret engine command.
func RenderVaultSecretRole(policyJSON string) string {
	var buf bytes.Buffer
	buf.WriteString("# HashiCorp Vault AWS Secret Engine Role Configuration:\n")
	buf.WriteString("vault write aws/roles/least-privilege-app \\\n")
	buf.WriteString("    credential_type=assumed_role \\\n")
	buf.WriteString("    role_arn=\"arn:aws:iam::${var.account_id}:role/AppRole\" \\\n")
	buf.WriteString("    policy_document=@- <<EOF\n")
	buf.WriteString(strings.TrimSpace(policyJSON) + "\n")
	buf.WriteString("EOF\n")
	return buf.String()
}
