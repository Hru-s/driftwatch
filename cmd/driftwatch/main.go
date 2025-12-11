package main

import (
	"flag"
	"log"

	"github.com/Hru-s/driftwatch/internal/app" // change to your module path if needed
)

func main() {
	mode := flag.String("mode", "single",
		"Mode: 'single' (baseline YAML vs live cluster) or 'cluster-compare' (cluster A vs cluster B)")

	baselineDir := flag.String("baseline", "",
		"Path to baseline policy YAML directory (RBAC, NetworkPolicy, PSA) for single mode")

	kubeconfig := flag.String("kubeconfig", "",
		"Path to kubeconfig file for the live cluster (single mode)")

	kubeconfigA := flag.String("kubeconfig-a", "",
		"Path to kubeconfig for baseline cluster A (cluster-compare mode)")

	kubeconfigB := flag.String("kubeconfig-b", "",
		"Path to kubeconfig for live cluster B (cluster-compare mode)")

	driftType := flag.String("drift-type", "extra",
		"Drift type: extra|missing|both ")

	ignoreSystem := flag.Bool("ignore-system", true,
		"Ignore kube-system and system:* subjects/namespaces when reporting drift (default true)")

	output := flag.String("output", "text",
		"Output format: text|json ")

	subjectKind := flag.String("subject-kind", "All",
		"Filter by subject kind: ServiceAccount|User|Group|All ")

	subjectName := flag.String("subject-name", "",
		"Filter by subject name (exact or /regex/)")

	subjectNamespace := flag.String("subject-namespace", "",
		"Filter by subject namespace (exact or /regex/)")

	flag.Parse()

	opts := app.Options{
		Mode:             *mode,
		BaselineDir:      *baselineDir,
		Kubeconfig:       *kubeconfig,
		KubeconfigA:      *kubeconfigA,
		KubeconfigB:      *kubeconfigB,
		DriftType:        *driftType,
		IgnoreSystem:     *ignoreSystem,
		SubjectKind:      *subjectKind,
		SubjectName:      *subjectName,
		SubjectNamespace: *subjectNamespace,
		OutputFormat:     *output,
	}

	if err := app.Run(opts); err != nil {
		log.Fatalf("error: %v", err)
	}
}
