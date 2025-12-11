package collectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Hru-s/driftwatch/internal/model"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
)

// CollectPSAFromCluster lists namespaces in the cluster and extracts PSA labels.
func CollectPSAFromCluster(ctx context.Context, client *kubernetes.Clientset) ([]model.NamespacePSA, error) {
	nsList, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}

	var out []model.NamespacePSA
	for _, ns := range nsList.Items {
		out = append(out, namespaceToPSA(&ns))
	}
	return out, nil
}

// CollectPSAFromBaselineDir scans a baseline YAML directory for Namespace
// manifests and extracts PSA labels from them.
func CollectPSAFromBaselineDir(dir string) ([]model.NamespacePSA, error) {
	var out []model.NamespacePSA

	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !isYAMLFile(path) {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("opening %s: %w", path, err)
		}
		defer f.Close()

		if err := decodePSANamespacesFromReader(f, &out); err != nil {
			return fmt.Errorf("decoding namespaces from %s: %w", path, err)
		}
		return nil
	})

	if walkErr != nil {
		return nil, walkErr
	}
	return out, nil
}

// --- helpers ---------------------------------------------------------------

func isYAMLFile(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

func decodePSANamespacesFromReader(r io.Reader, out *[]model.NamespacePSA) error {
	dec := yaml.NewYAMLOrJSONDecoder(r, 4096)

	for {
		var raw runtime.RawExtension
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		if len(raw.Raw) == 0 {
			continue
		}

		// Quick type check by decoding TypeMeta.
		var tm metav1.TypeMeta
		if err := json.Unmarshal(raw.Raw, &tm); err != nil {
			continue
		}
		if tm.Kind != "Namespace" {
			continue
		}

		var ns corev1.Namespace
		if err := json.Unmarshal(raw.Raw, &ns); err != nil {
			continue
		}
		*out = append(*out, namespaceToPSA(&ns))
	}

	return nil
}

func namespaceToPSA(ns *corev1.Namespace) model.NamespacePSA {
	get := func(key string) model.PSALevel {
		val := ns.Labels[key]
		if val == "" {
			return ""
		}
		return model.PSALevel(val)
	}

	return model.NamespacePSA{
		Namespace: ns.Name,
		Enforce:   get("pod-security.kubernetes.io/enforce"),
		Audit:     get("pod-security.kubernetes.io/audit"),
		Warn:      get("pod-security.kubernetes.io/warn"),
	}
}
