package model

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
)

// SubjectKey uniquely identifies a subject (User / Group / ServiceAccount).
type SubjectKey struct {
	Kind      string `json:"kind"`                // "User", "Group", "ServiceAccount"
	Name      string `json:"name"`                // subject name
	Namespace string `json:"namespace,omitempty"` // for ServiceAccount only
}

func (s SubjectKey) String() string {
	if s.Kind == "ServiceAccount" && s.Namespace != "" {
		return fmt.Sprintf("%s %s/%s", s.Kind, s.Namespace, s.Name)
	}
	if s.Namespace != "" {
		return fmt.Sprintf("%s %s/%s", s.Kind, s.Namespace, s.Name)
	}
	return fmt.Sprintf("%s %s", s.Kind, s.Name)
}

// Permission represents one effective permission a subject has.
type Permission struct {
	ScopeNamespace string `json:"scopeNamespace"`           // "*" for cluster-wide, or specific namespace
	APIGroup       string `json:"apiGroup"`                 // e.g. "", "apps"
	Resource       string `json:"resource"`                 // e.g. "pods", "deployments"
	ResourceName   string `json:"resourceName"`             // name or "*" if not constrained
	Verb           string `json:"verb"`                     // e.g. "get", "list", "watch"
	NonResourceURL string `json:"nonResourceUrl,omitempty"` // if NonResourceURL rule
}

func (p Permission) String() string {
	scope := "[cluster-wide]"
	if p.ScopeNamespace != "" && p.ScopeNamespace != "*" {
		scope = fmt.Sprintf("[ns=%s]", p.ScopeNamespace)
	}

	if p.NonResourceURL != "" {
		return fmt.Sprintf("%s verb=%s nonResourceURL=%s",
			scope, p.Verb, p.NonResourceURL)
	}

	group := p.APIGroup
	if group == "" {
		group = "core"
	}

	rn := p.ResourceName
	if rn == "" {
		rn = "*"
	}

	return fmt.Sprintf("%s verb=%s resource=%s.%s resourceName=%s",
		scope, p.Verb, p.Resource, group, rn)
}

// RBACSnapshot is a normalized view of effective permissions per subject.
type RBACSnapshot struct {
	Subjects map[SubjectKey]map[Permission]struct{}
}

// AddPermissions merges the given permissions into the snapshot for the subject.
func (s *RBACSnapshot) AddPermissions(subj SubjectKey, perms []Permission) {
	if len(perms) == 0 {
		return
	}
	if s.Subjects == nil {
		s.Subjects = make(map[SubjectKey]map[Permission]struct{})
	}
	permSet, ok := s.Subjects[subj]
	if !ok {
		permSet = make(map[Permission]struct{})
		s.Subjects[subj] = permSet
	}
	for _, p := range perms {
		permSet[p] = struct{}{}
	}
}

// SubjectKeyFromRBACSubject converts an RBAC Subject to our SubjectKey.
func SubjectKeyFromRBACSubject(subj rbacv1.Subject, defaultNamespace string) SubjectKey {
	ns := subj.Namespace
	if ns == "" && subj.Kind == "ServiceAccount" {
		ns = defaultNamespace
	}
	return SubjectKey{
		Kind:      subj.Kind,
		Name:      subj.Name,
		Namespace: ns,
	}
}

// ExpandPolicyRulesToPermissions converts PolicyRule objects into flat Permission entries.
// bindingNamespace is the namespace of the RoleBinding (if any).
// clusterScope should be true when rules are bound via a ClusterRoleBinding.
func ExpandPolicyRulesToPermissions(
	rules []rbacv1.PolicyRule,
	bindingNamespace string,
	clusterScope bool,
) []Permission {
	var out []Permission

	for _, rule := range rules {
		// Non-resource URLs
		if len(rule.NonResourceURLs) > 0 {
			scope := "*"
			for _, verb := range rule.Verbs {
				for _, url := range rule.NonResourceURLs {
					out = append(out, Permission{
						ScopeNamespace: scope,
						Verb:           verb,
						NonResourceURL: url,
					})
				}
			}
			continue
		}

		apiGroups := rule.APIGroups
		if len(apiGroups) == 0 {
			apiGroups = []string{""}
		}

		resources := rule.Resources
		if len(resources) == 0 {
			resources = []string{""}
		}

		resourceNames := rule.ResourceNames
		if len(resourceNames) == 0 {
			resourceNames = []string{"*"}
		}

		scope := "*"
		if !clusterScope {
			scope = bindingNamespace
		}

		for _, verb := range rule.Verbs {
			for _, group := range apiGroups {
				for _, res := range resources {
					for _, rn := range resourceNames {
						out = append(out, Permission{
							ScopeNamespace: scope,
							APIGroup:       group,
							Resource:       res,
							ResourceName:   rn,
							Verb:           verb,
						})
					}
				}
			}
		}
	}

	return out
}
