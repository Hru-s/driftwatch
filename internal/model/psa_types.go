package model

import "fmt"

// PSALevel represents a Pod Security Admission level.
type PSALevel string

const (
	PSALevelPrivileged PSALevel = "privileged"
	PSALevelBaseline   PSALevel = "baseline"
	PSALevelRestricted PSALevel = "restricted"
)

// NamespacePSA captures PSA-relevant labels for a namespace.
type NamespacePSA struct {
	Namespace string   `json:"namespace"`
	Enforce   PSALevel `json:"enforce,omitempty"`
	Audit     PSALevel `json:"audit,omitempty"`
	Warn      PSALevel `json:"warn,omitempty"`
}

func (n NamespacePSA) String() string {
	return fmt.Sprintf("ns=%s enforce=%s audit=%s warn=%s",
		n.Namespace, n.Enforce, n.Audit, n.Warn)
}

// PSADriftEntry is one namespace's PSA drift comparison.
type PSADriftEntry struct {
	Namespace string   `json:"namespace"`
	Baseline  PSALevel `json:"baseline,omitempty"`
	Live      PSALevel `json:"live,omitempty"`
	// DriftType: "extra", "missing", "weaker", "stronger", "different"
	DriftType string `json:"driftType"`
}
