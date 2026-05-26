package sealedsecrets

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"k8s.io/utils/ptr"

	"github.com/containers/kubernetes-mcp-server/pkg/api"
	"github.com/containers/kubernetes-mcp-server/pkg/output"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var sealedSecretGVR = schema.GroupVersionResource{
	Group:    "bitnami.com",
	Version:  "v1alpha1",
	Resource: "sealedsecrets",
}

func initSealedSecrets() []api.ServerTool {
	return []api.ServerTool{
		{
			Tool: api.Tool{
				Name: "sealed_secrets_update_key",
				Description: "Add or update a key in an existing Bitnami SealedSecret. " +
					"Generates a random secret value from a regex pattern, encrypts it with kubeseal, " +
					"and returns the updated SealedSecret YAML. Does NOT write to the cluster — " +
					"use the returned YAML in a merge request. The plaintext value is never exposed.",
				InputSchema: &jsonschema.Schema{
					Type: "object",
					Properties: map[string]*jsonschema.Schema{
						"name": {
							Type:        "string",
							Description: "Name of the SealedSecret resource",
						},
						"namespace": {
							Type:        "string",
							Description: "Namespace of the SealedSecret (required for kubeseal encryption scope)",
						},
						"key": {
							Type:        "string",
							Description: "The secret data key to add or update (e.g. \"database-password\", \"api-token\")",
						},
						"pattern": {
							Type: "string",
							Description: "Regex-like pattern for generating the secret value. " +
								"Supported: character classes [a-zA-Z0-9], shorthand \\d \\w, repetition {n} {n,m}, literals. " +
								"Examples: \"[a-zA-Z0-9]{32}\" (alphanumeric), \"[a-f0-9]{64}\" (hex), \"sk_live_\\w{24}\" (prefixed key)",
						},
						"scope": {
							Type: "string",
							Description: "Sealed Secrets encryption scope (Optional, default \"strict\"). " +
								"\"strict\": bound to namespace+name, \"namespace-wide\": bound to namespace, \"cluster-wide\": usable anywhere",
						},
						"controller_namespace": {
							Type:        "string",
							Description: "Namespace where the sealed-secrets controller runs (Optional, default \"kube-system\")",
						},
						"controller_name": {
							Type:        "string",
							Description: "Name of the sealed-secrets controller (Optional, default \"sealed-secrets-controller\")",
						},
					},
					Required: []string{"name", "namespace", "key", "pattern"},
				},
				Annotations: api.ToolAnnotations{
					Title:           "Sealed Secrets: Update Key",
					ReadOnlyHint:    ptr.To(true),
					DestructiveHint: ptr.To(false),
					IdempotentHint:  ptr.To(false),
					OpenWorldHint:   ptr.To(true),
				},
			},
			Handler: sealedSecretsUpdateKey,
		},
		{
			Tool: api.Tool{
				Name: "sealed_secrets_create",
				Description: "Create a new Bitnami SealedSecret with one or more generated keys. " +
					"Each key gets a random value from a regex pattern, encrypted with kubeseal. " +
					"Returns SealedSecret YAML without writing to the cluster. Plaintext is never exposed.",
				InputSchema: &jsonschema.Schema{
					Type: "object",
					Properties: map[string]*jsonschema.Schema{
						"name": {
							Type:        "string",
							Description: "Name for the new SealedSecret resource",
						},
						"namespace": {
							Type:        "string",
							Description: "Namespace for the new SealedSecret",
						},
						"keys": {
							Type:        "array",
							Description: "List of secret keys to generate. Each entry has \"key\" (name) and \"pattern\" (regex for value generation)",
							Items: &jsonschema.Schema{
								Type: "object",
								Properties: map[string]*jsonschema.Schema{
									"key": {
										Type:        "string",
										Description: "Secret data key name",
									},
									"pattern": {
										Type:        "string",
										Description: "Regex-like pattern for value generation",
									},
								},
								Required: []string{"key", "pattern"},
							},
						},
						"scope": {
							Type:        "string",
							Description: "Encryption scope (Optional, default \"strict\"): \"strict\", \"namespace-wide\", or \"cluster-wide\"",
						},
						"controller_namespace": {
							Type:        "string",
							Description: "Namespace of the sealed-secrets controller (Optional, default \"kube-system\")",
						},
						"controller_name": {
							Type:        "string",
							Description: "Name of the sealed-secrets controller (Optional, default \"sealed-secrets-controller\")",
						},
					},
					Required: []string{"name", "namespace", "keys"},
				},
				Annotations: api.ToolAnnotations{
					Title:           "Sealed Secrets: Create",
					ReadOnlyHint:    ptr.To(true),
					DestructiveHint: ptr.To(false),
					IdempotentHint:  ptr.To(false),
					OpenWorldHint:   ptr.To(true),
				},
			},
			Handler: sealedSecretsCreate,
		},
	}
}

// sealedSecretsUpdateKey adds or replaces a single key in an existing SealedSecret.
func sealedSecretsUpdateKey(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
	p := api.WrapParams(params)
	name := p.RequiredString("name")
	namespace := p.RequiredString("namespace")
	key := p.RequiredString("key")
	pattern := p.RequiredString("pattern")
	scope := p.OptionalString("scope", "strict")
	ctrlNs := p.OptionalString("controller_namespace", "kube-system")
	ctrlName := p.OptionalString("controller_name", "sealed-secrets-controller")
	if err := p.Err(); err != nil {
		return api.NewToolCallResult("", fmt.Errorf("invalid parameters: %w", err)), nil
	}

	if err := validateScope(scope); err != nil {
		return api.NewToolCallResult("", err), nil
	}

	// Fetch existing SealedSecret
	obj, err := params.DynamicClient().Resource(sealedSecretGVR).Namespace(namespace).Get(
		params.Context, name, metav1.GetOptions{},
	)
	if err != nil {
		return api.NewToolCallResult("", fmt.Errorf("failed to get SealedSecret %s/%s: %w", namespace, name, err)), nil
	}

	// Fetch controller's public cert via the k8s client (not kubeseal's own k8s access)
	certPEM, err := fetchControllerCert(params.Context, params.KubernetesClient, ctrlNs, ctrlName)
	if err != nil {
		return api.NewToolCallResult("", err), nil
	}

	// Generate and encrypt value
	encrypted, err := generateAndEncrypt(params.Context, certPEM, pattern, namespace, name, scope)
	if err != nil {
		return api.NewToolCallResult("", err), nil
	}

	// Merge into spec.encryptedData
	if err := mergeEncryptedKey(obj, key, encrypted); err != nil {
		return api.NewToolCallResult("", err), nil
	}

	// Strip managed fields and resource version for clean YAML output
	cleanForOutput(obj)

	yamlStr, err := output.MarshalYaml(obj.Object)
	if err != nil {
		return api.NewToolCallResult("", fmt.Errorf("failed to marshal YAML: %w", err)), nil
	}

	return api.NewToolCallResult(
		fmt.Sprintf("Updated SealedSecret %s/%s — added/updated key %q (encrypted, plaintext never exposed).\n"+
			"Apply this YAML via merge request:\n\n%s", namespace, name, key, yamlStr),
		nil,
	), nil
}

// sealedSecretsCreate creates a new SealedSecret from scratch with multiple generated keys.
func sealedSecretsCreate(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
	p := api.WrapParams(params)
	name := p.RequiredString("name")
	namespace := p.RequiredString("namespace")
	scope := p.OptionalString("scope", "strict")
	ctrlNs := p.OptionalString("controller_namespace", "kube-system")
	ctrlName := p.OptionalString("controller_name", "sealed-secrets-controller")
	if err := p.Err(); err != nil {
		return api.NewToolCallResult("", fmt.Errorf("invalid parameters: %w", err)), nil
	}

	if err := validateScope(scope); err != nil {
		return api.NewToolCallResult("", err), nil
	}

	// Extract keys array from raw params
	keysRaw, ok := params.GetArguments()["keys"]
	if !ok {
		return api.NewToolCallResult("", fmt.Errorf("missing required parameter: keys")), nil
	}
	keysArr, ok := keysRaw.([]interface{})
	if !ok {
		return api.NewToolCallResult("", fmt.Errorf("keys must be an array")), nil
	}
	if len(keysArr) == 0 {
		return api.NewToolCallResult("", fmt.Errorf("keys array must not be empty")), nil
	}

	// Fetch controller's public cert via the k8s client
	certPEM, err := fetchControllerCert(params.Context, params.KubernetesClient, ctrlNs, ctrlName)
	if err != nil {
		return api.NewToolCallResult("", err), nil
	}

	encryptedData := make(map[string]interface{})
	var keyNames []string

	for i, entry := range keysArr {
		entryMap, ok := entry.(map[string]interface{})
		if !ok {
			return api.NewToolCallResult("", fmt.Errorf("keys[%d]: must be an object with \"key\" and \"pattern\"", i)), nil
		}
		keyName, _ := entryMap["key"].(string)
		pattern, _ := entryMap["pattern"].(string)
		if keyName == "" || pattern == "" {
			return api.NewToolCallResult("", fmt.Errorf("keys[%d]: both \"key\" and \"pattern\" are required", i)), nil
		}

		encrypted, err := generateAndEncrypt(params.Context, certPEM, pattern, namespace, name, scope)
		if err != nil {
			return api.NewToolCallResult("", fmt.Errorf("keys[%d] (%s): %w", i, keyName, err)), nil
		}
		encryptedData[keyName] = encrypted
		keyNames = append(keyNames, keyName)
	}

	// Build SealedSecret object
	annotations := map[string]interface{}{}
	if scope != "strict" {
		annotations["sealedsecrets.bitnami.com/"+scopeAnnotationKey(scope)] = "true"
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "bitnami.com/v1alpha1",
			"kind":       "SealedSecret",
			"metadata": map[string]interface{}{
				"name":        name,
				"namespace":   namespace,
				"annotations": annotations,
			},
			"spec": map[string]interface{}{
				"encryptedData": encryptedData,
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":      name,
						"namespace": namespace,
					},
					"type": "Opaque",
				},
			},
		},
	}

	yamlStr, err := output.MarshalYaml(obj.Object)
	if err != nil {
		return api.NewToolCallResult("", fmt.Errorf("failed to marshal YAML: %w", err)), nil
	}

	return api.NewToolCallResult(
		fmt.Sprintf("Created SealedSecret %s/%s with %d key(s): %s (encrypted, plaintext never exposed).\n"+
			"Apply this YAML via merge request:\n\n%s",
			namespace, name, len(keyNames), strings.Join(keyNames, ", "), yamlStr),
		nil,
	), nil
}

// fetchControllerCert retrieves the sealed-secrets controller's public certificate
// via the k8s API service proxy, using the MCP server's existing k8s client.
// This avoids kubeseal needing its own k8s access.
func fetchControllerCert(ctx context.Context, client api.KubernetesClient, ctrlNs, ctrlName string) ([]byte, error) {
	// The sealed-secrets controller exposes its cert at /v1/cert.pem via a Service.
	// We use the k8s API server's service proxy to reach it.
	result := client.CoreV1().Services(ctrlNs).ProxyGet("http", ctrlName, "", "/v1/cert.pem", nil)
	raw, err := result.DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to fetch sealed-secrets controller certificate from %s/%s: %w\n"+
				"Ensure the sealed-secrets controller is running and the service is accessible",
			ctrlNs, ctrlName, err,
		)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("sealed-secrets controller returned empty certificate")
	}
	return raw, nil
}

// generateAndEncrypt generates a random value from the pattern, then encrypts it with kubeseal --raw.
func generateAndEncrypt(ctx context.Context, certPEM []byte, pattern, namespace, name, scope string) (string, error) {
	// Generate random value from pattern
	plaintext, err := generateFromPattern(pattern)
	if err != nil {
		return "", fmt.Errorf("failed to generate value from pattern %q: %w", pattern, err)
	}
	if plaintext == "" {
		return "", fmt.Errorf("pattern %q produced empty value", pattern)
	}

	// Encrypt with kubeseal --raw using the pre-fetched certificate
	encrypted, err := kubesealRaw(ctx, certPEM, plaintext, namespace, name, scope)
	if err != nil {
		return "", err
	}

	return encrypted, nil
}

// kubesealRaw encrypts a single value using kubeseal --raw with a pre-fetched
// controller certificate. This means kubeseal performs pure local encryption
// and does NOT need its own k8s access.
// Input: raw plaintext value + controller cert PEM.
// Output: base64-encoded encrypted value for spec.encryptedData.
func kubesealRaw(ctx context.Context, certPEM []byte, value, namespace, name, scope string) (string, error) {
	// Write cert to a temp file for kubeseal --cert
	certFile, err := os.CreateTemp("", "sealed-secrets-cert-*.pem")
	if err != nil {
		return "", fmt.Errorf("failed to create temp cert file: %w", err)
	}
	defer os.Remove(certFile.Name())
	defer certFile.Close()

	if _, err := certFile.Write(certPEM); err != nil {
		return "", fmt.Errorf("failed to write cert file: %w", err)
	}
	if err := certFile.Close(); err != nil {
		return "", fmt.Errorf("failed to close cert file: %w", err)
	}

	args := []string{
		"--raw",
		"--from-file=/dev/stdin",
		"--namespace", namespace,
		"--name", name,
		"--cert", certFile.Name(),
	}

	if scope != "" && scope != "strict" {
		args = append(args, "--scope", scope)
	}

	cmd := exec.CommandContext(ctx, "kubeseal", args...)
	cmd.Stdin = strings.NewReader(value)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		stderrStr := strings.TrimSpace(stderr.String())
		if stderrStr != "" {
			return "", fmt.Errorf("kubeseal --raw failed: %s: %w", stderrStr, err)
		}
		// Check if kubeseal is installed
		if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
			return "", fmt.Errorf("kubeseal binary not found in PATH — install it from https://github.com/bitnami-labs/sealed-secrets/releases")
		}
		return "", fmt.Errorf("kubeseal --raw failed: %w", err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// mergeEncryptedKey sets spec.encryptedData[key] = encrypted on the SealedSecret object.
func mergeEncryptedKey(obj *unstructured.Unstructured, key, encrypted string) error {
	spec, ok := obj.Object["spec"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("SealedSecret has no spec field")
	}

	encData, ok := spec["encryptedData"].(map[string]interface{})
	if !ok {
		encData = make(map[string]interface{})
		spec["encryptedData"] = encData
	}

	encData[key] = encrypted
	return nil
}

// cleanForOutput removes fields that are noisy in YAML output for merge requests.
func cleanForOutput(obj *unstructured.Unstructured) {
	meta, ok := obj.Object["metadata"].(map[string]interface{})
	if !ok {
		return
	}
	delete(meta, "managedFields")
	delete(meta, "resourceVersion")
	delete(meta, "uid")
	delete(meta, "creationTimestamp")
	delete(meta, "generation")

	delete(obj.Object, "status")
}

func validateScope(scope string) error {
	switch scope {
	case "strict", "namespace-wide", "cluster-wide":
		return nil
	default:
		return fmt.Errorf("invalid scope %q: must be \"strict\", \"namespace-wide\", or \"cluster-wide\"", scope)
	}
}

func scopeAnnotationKey(scope string) string {
	switch scope {
	case "namespace-wide":
		return "namespace-wide"
	case "cluster-wide":
		return "cluster-wide"
	default:
		return ""
	}
}
