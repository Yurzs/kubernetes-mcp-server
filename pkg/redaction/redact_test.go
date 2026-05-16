package redaction

import (
	"strings"
	"testing"

	"github.com/containers/kubernetes-mcp-server/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestRedactorSecretDataOpaque(t *testing.T) {
	// Config: redact data.* on v1 Secret with opaque mode
	redactor := NewRedactor([]api.GroupVersionKind{
		{
			Group:          "",
			Version:        "v1",
			Kind:           "Secret",
			RedactedFields: []string{"data.*", "stringData.*"},
			RedactionMode:  "opaque",
		},
	})

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]interface{}{
				"name":      "my-secret",
				"namespace": "default",
			},
			"type": "Opaque",
			"data": map[string]interface{}{
				"DATABASE_PASSWORD": "c2VjcmV0cGFzc3dvcmQ=",
				"API_KEY":           "bXlhcGlrZXk=",
			},
			"stringData": map[string]interface{}{
				"config.yaml": "sensitive: true\npassword: hunter2",
			},
		},
	}

	redactor.Apply(obj)

	data := obj.Object["data"].(map[string]interface{})
	assert.Equal(t, "[REDACTED]", data["DATABASE_PASSWORD"])
	assert.Equal(t, "[REDACTED]", data["API_KEY"])

	stringData := obj.Object["stringData"].(map[string]interface{})
	assert.Equal(t, "[REDACTED]", stringData["config.yaml"])

	// Metadata should be untouched
	metadata := obj.Object["metadata"].(map[string]interface{})
	assert.Equal(t, "my-secret", metadata["name"])
	assert.Equal(t, "default", metadata["namespace"])
	assert.Equal(t, "Opaque", obj.Object["type"])
}

func TestRedactorSecretDataHashed(t *testing.T) {
	redactor := NewRedactor([]api.GroupVersionKind{
		{
			Group:          "",
			Version:        "v1",
			Kind:           "Secret",
			RedactedFields: []string{"data.*"},
			RedactionMode:  "hashed",
		},
	})

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]interface{}{
				"name": "my-secret",
			},
			"data": map[string]interface{}{
				"PASSWORD": "secret123",
				"TOKEN":    "secret123",
			},
		},
	}

	redactor.Apply(obj)

	data := obj.Object["data"].(map[string]interface{})
	passwordVal := data["PASSWORD"].(string)
	tokenVal := data["TOKEN"].(string)

	// Both should be redacted with hashes
	assert.True(t, strings.HasPrefix(passwordVal, "[REDACTED:gen_"))
	assert.True(t, strings.HasPrefix(tokenVal, "[REDACTED:gen_"))

	// Same input values should produce same hash
	assert.Equal(t, passwordVal, tokenVal, "same original values should produce same redacted hash")
}

func TestRedactorDeploymentEnvValues(t *testing.T) {
	redactor := NewRedactor([]api.GroupVersionKind{
		{
			Group:          "apps",
			Version:        "v1",
			Kind:           "Deployment",
			RedactedFields: []string{"spec.template.spec.containers.*.env.*.value"},
			RedactionMode:  "opaque",
		},
	})

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "web-app",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "app",
								"image": "myapp:latest",
								"env": []interface{}{
									map[string]interface{}{
										"name":  "PORT",
										"value": "3000",
									},
									map[string]interface{}{
										"name":  "NODE_ENV",
										"value": "production",
									},
									map[string]interface{}{
										"name": "DB_PASSWORD",
										"valueFrom": map[string]interface{}{
											"secretKeyRef": map[string]interface{}{
												"name": "db-secret",
												"key":  "password",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	redactor.Apply(obj)

	containers := obj.Object["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["containers"].([]interface{})
	env := containers[0].(map[string]interface{})["env"].([]interface{})

	// Plain env values should be redacted
	env0 := env[0].(map[string]interface{})
	assert.Equal(t, "PORT", env0["name"])
	assert.Equal(t, "[REDACTED]", env0["value"])

	env1 := env[1].(map[string]interface{})
	assert.Equal(t, "NODE_ENV", env1["name"])
	assert.Equal(t, "[REDACTED]", env1["value"])

	// secretKeyRef should be untouched
	env2 := env[2].(map[string]interface{})
	assert.Equal(t, "DB_PASSWORD", env2["name"])
	require.Nil(t, env2["value"], "secretKeyRef env should not have value field added")
	secretRef := env2["valueFrom"].(map[string]interface{})["secretKeyRef"].(map[string]interface{})
	assert.Equal(t, "db-secret", secretRef["name"])
	assert.Equal(t, "password", secretRef["key"])
}

func TestRedactorNoMatchingGVK(t *testing.T) {
	redactor := NewRedactor([]api.GroupVersionKind{
		{
			Group:          "",
			Version:        "v1",
			Kind:           "Secret",
			RedactedFields: []string{"data.*"},
		},
	})

	// ConfigMap should not be affected
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"data": map[string]interface{}{
				"config": "visible-value",
			},
		},
	}

	redactor.Apply(obj)

	data := obj.Object["data"].(map[string]interface{})
	assert.Equal(t, "visible-value", data["config"], "non-matching GVK should not be redacted")
}

func TestRedactorEmptyRedactedFields(t *testing.T) {
	redactor := NewRedactor([]api.GroupVersionKind{
		{
			Group:   "",
			Version: "v1",
			Kind:    "Secret",
			// No RedactedFields - should not produce rules
		},
	})

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"data": map[string]interface{}{
				"PASSWORD": "should-stay",
			},
		},
	}

	redactor.Apply(obj)
	data := obj.Object["data"].(map[string]interface{})
	assert.Equal(t, "should-stay", data["PASSWORD"])
}

func TestRedactorDefaultsToOpaque(t *testing.T) {
	redactor := NewRedactor([]api.GroupVersionKind{
		{
			Group:          "",
			Version:        "v1",
			Kind:           "Secret",
			RedactedFields: []string{"data.*"},
			// RedactionMode not set - should default to opaque
		},
	})

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"data": map[string]interface{}{
				"KEY": "value",
			},
		},
	}

	redactor.Apply(obj)
	data := obj.Object["data"].(map[string]interface{})
	assert.Equal(t, "[REDACTED]", data["KEY"])
}

func TestRedactorApplyToList(t *testing.T) {
	redactor := NewRedactor([]api.GroupVersionKind{
		{
			Group:          "",
			Version:        "v1",
			Kind:           "Secret",
			RedactedFields: []string{"data.*"},
		},
	})

	list := &unstructured.UnstructuredList{
		Items: []unstructured.Unstructured{
			{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Secret",
					"metadata":   map[string]interface{}{"name": "secret-1"},
					"data":       map[string]interface{}{"KEY": "value1"},
				},
			},
			{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Secret",
					"metadata":   map[string]interface{}{"name": "secret-2"},
					"data":       map[string]interface{}{"KEY": "value2"},
				},
			},
		},
	}

	redactor.ApplyToList(list)

	for _, item := range list.Items {
		data := item.Object["data"].(map[string]interface{})
		assert.Equal(t, "[REDACTED]", data["KEY"])
	}
}

func TestRedactorInitContainers(t *testing.T) {
	redactor := NewRedactor([]api.GroupVersionKind{
		{
			Group:   "apps",
			Version: "v1",
			Kind:    "Deployment",
			RedactedFields: []string{
				"spec.template.spec.containers.*.env.*.value",
				"spec.template.spec.initContainers.*.env.*.value",
			},
		},
	})

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]interface{}{"name": "app"},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"initContainers": []interface{}{
							map[string]interface{}{
								"name": "init",
								"env": []interface{}{
									map[string]interface{}{
										"name":  "INIT_SECRET",
										"value": "init-secret-val",
									},
								},
							},
						},
						"containers": []interface{}{
							map[string]interface{}{
								"name": "main",
								"env": []interface{}{
									map[string]interface{}{
										"name":  "APP_SECRET",
										"value": "app-secret-val",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	redactor.Apply(obj)

	spec := obj.Object["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})

	initEnv := spec["initContainers"].([]interface{})[0].(map[string]interface{})["env"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "INIT_SECRET", initEnv["name"])
	assert.Equal(t, "[REDACTED]", initEnv["value"])

	mainEnv := spec["containers"].([]interface{})[0].(map[string]interface{})["env"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "APP_SECRET", mainEnv["name"])
	assert.Equal(t, "[REDACTED]", mainEnv["value"])
}

func TestRedactorHashedGenerationID(t *testing.T) {
	redactor := NewRedactor([]api.GroupVersionKind{
		{
			Group:          "",
			Version:        "v1",
			Kind:           "Secret",
			RedactedFields: []string{"data.*"},
			RedactionMode:  "hashed",
		},
	})

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"data": map[string]interface{}{
				"KEY": "value",
			},
		},
	}

	redactor.Apply(obj)

	data := obj.Object["data"].(map[string]interface{})
	val := data["KEY"].(string)

	// Should contain generation ID
	genID := redactor.salt.GenerationID()
	assert.Contains(t, val, "gen_"+genID)
}

func TestRedactorMissingField(t *testing.T) {
	// Field path points to something that doesn't exist - should not panic
	redactor := NewRedactor([]api.GroupVersionKind{
		{
			Group:          "",
			Version:        "v1",
			Kind:           "Secret",
			RedactedFields: []string{"nonexistent.path.*"},
		},
	})

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"data": map[string]interface{}{
				"KEY": "should-remain",
			},
		},
	}

	// Should not panic
	redactor.Apply(obj)

	data := obj.Object["data"].(map[string]interface{})
	assert.Equal(t, "should-remain", data["KEY"])
}

func TestRedactorNilObject(t *testing.T) {
	redactor := NewRedactor([]api.GroupVersionKind{
		{
			Group:          "",
			Version:        "v1",
			Kind:           "Secret",
			RedactedFields: []string{"data.*"},
		},
	})

	// Should not panic on nil
	redactor.Apply(nil)
}
