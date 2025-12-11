package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Hru-s/driftwatch/internal/model"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
)

// CollectNetPolFromCluster builds a normalized snapshot of NetworkPolicies
// from a live cluster.
func CollectNetPolFromCluster(
	ctx context.Context,
	client kubernetes.Interface,
) (*model.NetPolSnapshot, error) {
	netpols, err := client.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing NetworkPolicies: %w", err)
	}
	return buildNetPolSnapshot(netpols.Items)
}

// CollectNetPolFromBaselineDir reads NetworkPolicy YAMLs from a baseline directory.
func CollectNetPolFromBaselineDir(dir string) (*model.NetPolSnapshot, error) {
	netpols, err := loadNetPolYAMLFromDir(dir)
	if err != nil {
		return nil, err
	}
	return buildNetPolSnapshot(netpols)
}

func buildNetPolSnapshot(netpols []networkingv1.NetworkPolicy) (*model.NetPolSnapshot, error) {
	snap := &model.NetPolSnapshot{
		Items: make(map[string]model.NetPolDigest),
	}
	for _, np := range netpols {
		digest, err := model.NewNetPolDigest(&np)
		if err != nil {
			return nil, err
		}
		key := np.Namespace + "/" + np.Name
		snap.Items[key] = digest
	}
	return snap, nil
}

func loadNetPolYAMLFromDir(dir string) ([]networkingv1.NetworkPolicy, error) {
	var netpols []networkingv1.NetworkPolicy

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		name := strings.ToLower(info.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()

		dec := yamlutil.NewYAMLOrJSONDecoder(f, 4096)
		for {
			var raw map[string]interface{}
			if err := dec.Decode(&raw); err != nil {
				if err == io.EOF {
					break
				}
				return fmt.Errorf("decode %s: %w", path, err)
			}
			if len(raw) == 0 {
				continue
			}

			kind, _ := raw["kind"].(string)
			if kind != "NetworkPolicy" {
				continue
			}

			b, err := json.Marshal(raw)
			if err != nil {
				return fmt.Errorf("marshal %s: %w", path, err)
			}

			var np networkingv1.NetworkPolicy
			if err := json.Unmarshal(b, &np); err == nil {
				netpols = append(netpols, np)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return netpols, nil
}
