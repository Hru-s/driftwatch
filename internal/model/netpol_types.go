package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
)

// NetPolDigest is a light-weight normalized representation of a NetworkPolicy.
type NetPolDigest struct {
	Namespace    string                    `json:"namespace"`
	Name         string                    `json:"name"`
	SpecHash     string                    `json:"specHash"`
	PolicyTypes  []networkingv1.PolicyType `json:"policyTypes"`
	IngressCount int                       `json:"ingressCount"`
	EgressCount  int                       `json:"egressCount"`
}

func NewNetPolDigest(np *networkingv1.NetworkPolicy) (NetPolDigest, error) {
	specBytes, err := json.Marshal(np.Spec)
	if err != nil {
		return NetPolDigest{}, fmt.Errorf("marshal NetworkPolicy spec: %w", err)
	}
	hash := sha256.Sum256(specBytes)

	return NetPolDigest{
		Namespace:    np.Namespace,
		Name:         np.Name,
		SpecHash:     hex.EncodeToString(hash[:]),
		PolicyTypes:  np.Spec.PolicyTypes,
		IngressCount: len(np.Spec.Ingress),
		EgressCount:  len(np.Spec.Egress),
	}, nil
}

type NetPolRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func (r NetPolRef) String() string {
	return fmt.Sprintf("%s/%s", r.Namespace, r.Name)
}

type NetPolChange struct {
	Namespace string       `json:"namespace"`
	Name      string       `json:"name"`
	Baseline  NetPolDigest `json:"baseline"`
	Live      NetPolDigest `json:"live"`
}

type NetPolSnapshot struct {
	Items map[string]NetPolDigest `json:"-"`
}
