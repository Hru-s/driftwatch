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

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
)

// CollectRBACFromCluster normalizes effective RBAC from a live cluster.
func CollectRBACFromCluster(
	ctx context.Context,
	client kubernetes.Interface,
) (*model.RBACSnapshot, error) {
	rolesList, err := client.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing Roles: %w", err)
	}
	clusterRolesList, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing ClusterRoles: %w", err)
	}
	roleBindingsList, err := client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing RoleBindings: %w", err)
	}
	clusterRoleBindingsList, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing ClusterRoleBindings: %w", err)
	}

	return buildRBACSnapshot(
		rolesList.Items,
		clusterRolesList.Items,
		roleBindingsList.Items,
		clusterRoleBindingsList.Items,
	), nil
}

// CollectRBACFromBaselineDir reads RBAC YAML (Roles, ClusterRoles, *Bindings)
// from a baseline directory and builds a normalized snapshot.
func CollectRBACFromBaselineDir(dir string) (*model.RBACSnapshot, error) {
	roles, clusterRoles, roleBindings, clusterRoleBindings, err := loadRBACYAMLFromDir(dir)
	if err != nil {
		return nil, err
	}
	return buildRBACSnapshot(roles, clusterRoles, roleBindings, clusterRoleBindings), nil
}

func buildRBACSnapshot(
	roles []rbacv1.Role,
	clusterRoles []rbacv1.ClusterRole,
	roleBindings []rbacv1.RoleBinding,
	clusterRoleBindings []rbacv1.ClusterRoleBinding,
) *model.RBACSnapshot {
	snapshot := &model.RBACSnapshot{
		Subjects: make(map[model.SubjectKey]map[model.Permission]struct{}),
	}

	rolesByKey := make(map[string][]rbacv1.PolicyRule)
	for _, r := range roles {
		key := r.Namespace + "/" + r.Name
		rolesByKey[key] = append(rolesByKey[key], r.Rules...)
	}

	clusterRolesByName := make(map[string][]rbacv1.PolicyRule)
	for _, cr := range clusterRoles {
		clusterRolesByName[cr.Name] = append(clusterRolesByName[cr.Name], cr.Rules...)
	}

	// namespaced RoleBindings
	for _, rb := range roleBindings {
		var rules []rbacv1.PolicyRule
		switch rb.RoleRef.Kind {
		case "Role":
			key := rb.Namespace + "/" + rb.RoleRef.Name
			rules = rolesByKey[key]
		case "ClusterRole":
			rules = clusterRolesByName[rb.RoleRef.Name]
		default:
			continue
		}
		if len(rules) == 0 {
			continue
		}

		perms := model.ExpandPolicyRulesToPermissions(rules, rb.Namespace, false)
		if len(perms) == 0 {
			continue
		}

		for _, subj := range rb.Subjects {
			subjKey := model.SubjectKeyFromRBACSubject(subj, rb.Namespace)
			snapshot.AddPermissions(subjKey, perms)
		}
	}

	// ClusterRoleBindings (cluster-scope)
	for _, crb := range clusterRoleBindings {
		rules := clusterRolesByName[crb.RoleRef.Name]
		if len(rules) == 0 {
			continue
		}

		perms := model.ExpandPolicyRulesToPermissions(rules, "", true)
		if len(perms) == 0 {
			continue
		}

		for _, subj := range crb.Subjects {
			subjKey := model.SubjectKeyFromRBACSubject(subj, "")
			snapshot.AddPermissions(subjKey, perms)
		}
	}

	return snapshot
}

func loadRBACYAMLFromDir(dir string) (
	[]rbacv1.Role,
	[]rbacv1.ClusterRole,
	[]rbacv1.RoleBinding,
	[]rbacv1.ClusterRoleBinding,
	error,
) {
	var roles []rbacv1.Role
	var clusterRoles []rbacv1.ClusterRole
	var roleBindings []rbacv1.RoleBinding
	var clusterRoleBindings []rbacv1.ClusterRoleBinding

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
			if kind == "" {
				continue
			}

			b, err := json.Marshal(raw)
			if err != nil {
				return fmt.Errorf("marshal %s: %w", path, err)
			}

			switch kind {
			case "Role":
				var r rbacv1.Role
				if err := json.Unmarshal(b, &r); err == nil {
					roles = append(roles, r)
				}
			case "ClusterRole":
				var cr rbacv1.ClusterRole
				if err := json.Unmarshal(b, &cr); err == nil {
					clusterRoles = append(clusterRoles, cr)
				}
			case "RoleBinding":
				var rb rbacv1.RoleBinding
				if err := json.Unmarshal(b, &rb); err == nil {
					roleBindings = append(roleBindings, rb)
				}
			case "ClusterRoleBinding":
				var crb rbacv1.ClusterRoleBinding
				if err := json.Unmarshal(b, &crb); err == nil {
					clusterRoleBindings = append(clusterRoleBindings, crb)
				}
			default:
				// ignore other Kinds
			}
		}

		return nil
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return roles, clusterRoles, roleBindings, clusterRoleBindings, nil
}
