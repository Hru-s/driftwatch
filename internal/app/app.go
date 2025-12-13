package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Hru-s/driftwatch/internal/collectors"
	"github.com/Hru-s/driftwatch/internal/diff"
	"github.com/Hru-s/driftwatch/internal/kube"
	"github.com/Hru-s/driftwatch/internal/model"
)

type Options struct {
	Mode string

	BaselineDir string
	Kubeconfig  string
	KubeconfigA string
	KubeconfigB string

	DriftType    string
	IgnoreSystem bool

	SubjectKind      string
	SubjectName      string
	SubjectNamespace string

	OutputFormat string
}

func Run(opts Options) error {
	switch opts.Mode {
	case "single":
		return runSingle(opts)
	case "cluster-compare":
		return runClusterCompare(opts)
	default:
		return fmt.Errorf("unknown mode: %s (supported: single, cluster-compare)", opts.Mode)
	}
}

func runSingle(opts Options) error {
	if opts.BaselineDir == "" {
		return fmt.Errorf("-baseline is required in single mode")
	}
	if opts.Kubeconfig == "" {
		return fmt.Errorf("-kubeconfig is required in single mode")
	}

	clientLive, err := kube.BuildClient(opts.Kubeconfig)
	if err != nil {
		return fmt.Errorf("creating client for live cluster: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// -------- RBAC --------
	rbacBaseline, err := collectors.CollectRBACFromBaselineDir(opts.BaselineDir)
	if err != nil {
		return fmt.Errorf("loading baseline RBAC from %s: %w", opts.BaselineDir, err)
	}
	rbacLive, err := collectors.CollectRBACFromCluster(ctx, clientLive)
	if err != nil {
		return fmt.Errorf("collecting RBAC from live cluster: %w", err)
	}
	rbacDrift := diff.DiffRBAC(rbacBaseline, rbacLive)

	// ------ NetworkPolicy ------
	netpolBaseline, err := collectors.CollectNetPolFromBaselineDir(opts.BaselineDir)
	if err != nil {
		return fmt.Errorf("loading baseline NetworkPolicies from %s: %w", opts.BaselineDir, err)
	}
	netpolLive, err := collectors.CollectNetPolFromCluster(ctx, clientLive)
	if err != nil {
		return fmt.Errorf("collecting NetworkPolicies from live cluster: %w", err)
	}
	netpolDrift := diff.DiffNetworkPolicies(netpolBaseline, netpolLive)

	// ------ PSA (Pod Security Admission) ------
	psaBaseline, err := collectors.CollectPSAFromBaselineDir(opts.BaselineDir)
	if err != nil {
		return fmt.Errorf("loading baseline PSA from %s: %w", opts.BaselineDir, err)
	}
	psaLive, err := collectors.CollectPSAFromCluster(ctx, clientLive)
	if err != nil {
		return fmt.Errorf("collecting PSA from live cluster: %w", err)
	}
	psaDrift := diff.DiffPSA(psaBaseline, psaLive)

	modeLabel := "single (baseline YAML vs live cluster)"
	return renderReport(modeLabel, opts, rbacDrift, netpolDrift, psaDrift)
}

func runClusterCompare(opts Options) error {
	if opts.KubeconfigA == "" || opts.KubeconfigB == "" {
		return fmt.Errorf("both -kubeconfig-a and -kubeconfig-b are required for cluster-compare mode")
	}

	clientA, err := kube.BuildClient(opts.KubeconfigA)
	if err != nil {
		return fmt.Errorf("creating client for baseline cluster A: %w", err)
	}
	clientB, err := kube.BuildClient(opts.KubeconfigB)
	if err != nil {
		return fmt.Errorf("creating client for live cluster B: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// -------- RBAC --------
	rbacA, err := collectors.CollectRBACFromCluster(ctx, clientA)
	if err != nil {
		return fmt.Errorf("collecting RBAC from cluster A: %w", err)
	}
	rbacB, err := collectors.CollectRBACFromCluster(ctx, clientB)
	if err != nil {
		return fmt.Errorf("collecting RBAC from cluster B: %w", err)
	}
	rbacDrift := diff.DiffRBAC(rbacA, rbacB)

	// ------ NetworkPolicy ------
	netpolA, err := collectors.CollectNetPolFromCluster(ctx, clientA)
	if err != nil {
		return fmt.Errorf("collecting NetworkPolicies from cluster A: %w", err)
	}
	netpolB, err := collectors.CollectNetPolFromCluster(ctx, clientB)
	if err != nil {
		return fmt.Errorf("collecting NetworkPolicies from cluster B: %w", err)
	}
	netpolDrift := diff.DiffNetworkPolicies(netpolA, netpolB)

	// ------ PSA (Pod Security Admission) ------
	psaA, err := collectors.CollectPSAFromCluster(ctx, clientA)
	if err != nil {
		return fmt.Errorf("collecting PSA from cluster A: %w", err)
	}
	psaB, err := collectors.CollectPSAFromCluster(ctx, clientB)
	if err != nil {
		return fmt.Errorf("collecting PSA from cluster B: %w", err)
	}
	psaDrift := diff.DiffPSA(psaA, psaB)

	modeLabel := "cluster-compare (cluster A vs cluster B)"
	return renderReport(modeLabel, opts, rbacDrift, netpolDrift, psaDrift)
}

// -----------------------------------------------------------------------------
// Reporting helpers
// -----------------------------------------------------------------------------

func normalizeOutputFormat(s string) string {
	switch strings.ToLower(s) {
	case "json":
		return "json"
	case "text", "":
		return "text"
	default:
		return "text"
	}
}

func normalizeDriftType(s string) string {
	switch strings.ToLower(s) {
	case "missing":
		return "missing"
	case "both":
		return "both"
	case "extra", "":
		return "extra"
	default:
		return "extra"
	}
}

func renderReport(
	modeLabel string,
	opts Options,
	rbacDrift diff.RBACDrift,
	netpolDrift diff.NetPolDrift,
	psaDrift diff.PSADrift,
) error {
	opts.DriftType = normalizeDriftType(opts.DriftType)
	opts.OutputFormat = normalizeOutputFormat(opts.OutputFormat)

	switch opts.OutputFormat {
	case "json":
		return printJSONReport(modeLabel, opts, rbacDrift, netpolDrift, psaDrift)
	default:
		printHumanReport(modeLabel, opts, rbacDrift, netpolDrift, psaDrift)
		return nil
	}
}

// ---- filtering helpers ----

func isSystemSubject(s model.SubjectKey) bool {
	if s.Kind == "User" || s.Kind == "Group" {
		if strings.HasPrefix(s.Name, "system:") {
			return true
		}
	}
	if s.Kind == "ServiceAccount" {
		if s.Namespace == "kube-system" || s.Namespace == "kube-public" {
			return true
		}
	}
	return false
}

func isSystemNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public":
		return true
	default:
		return false
	}
}

func matchesSubjectKind(s model.SubjectKey, filter string) bool {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" || filter == "all" {
		return true
	}
	return strings.ToLower(s.Kind) == filter
}

func matchesSubjectNamespace(s model.SubjectKey, ns string) bool {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return true
	}
	return s.Namespace == ns
}

func matchesSubjectName(name, filter string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return true
	}

	// Regex style: /pattern/
	if len(filter) >= 2 && filter[0] == '/' && filter[len(filter)-1] == '/' {
		pattern := filter[1 : len(filter)-1]
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(name)
	}

	return name == filter
}

// -----------------------------------------------------------------------------
// JSON representation
// -----------------------------------------------------------------------------

type subjectPermissions struct {
	Subject     model.SubjectKey   `json:"subject"`
	Permissions []model.Permission `json:"permissions"`
}

type rbacDriftJSON struct {
	Extra   []subjectPermissions `json:"extra,omitempty"`
	Missing []subjectPermissions `json:"missing,omitempty"`
}

type netPolDriftJSON struct {
	Missing []model.NetPolRef    `json:"missing,omitempty"`
	Extra   []model.NetPolRef    `json:"extra,omitempty"`
	Changed []model.NetPolChange `json:"changed,omitempty"`
}

type psaDriftJSON struct {
	Extra   []model.PSADriftEntry `json:"extra,omitempty"`
	Missing []model.PSADriftEntry `json:"missing,omitempty"`
}

type driftReportJSON struct {
	Mode             string `json:"mode"`
	DriftType        string `json:"driftType"`
	IgnoreSystem     bool   `json:"ignoreSystem"`
	SubjectKind      string `json:"subjectKind"`
	SubjectName      string `json:"subjectName"`
	SubjectNamespace string `json:"subjectNamespace"`

	RBAC          rbacDriftJSON   `json:"rbac"`
	NetworkPolicy netPolDriftJSON `json:"networkPolicy"`
	PSA           psaDriftJSON    `json:"psa"`
}

func filterRBACDriftToSlices(d diff.RBACDrift, opts Options) ([]subjectPermissions, []subjectPermissions) {
	extraOut := []subjectPermissions{}
	missingOut := []subjectPermissions{}

	// stable ordering
	subjectsExtra := make([]model.SubjectKey, 0, len(d.Extra))
	for s := range d.Extra {
		subjectsExtra = append(subjectsExtra, s)
	}
	sort.Slice(subjectsExtra, func(i, j int) bool {
		return subjectsExtra[i].String() < subjectsExtra[j].String()
	})

	for _, subj := range subjectsExtra {
		perms := d.Extra[subj]
		if opts.IgnoreSystem && isSystemSubject(subj) {
			continue
		}
		if !matchesSubjectKind(subj, opts.SubjectKind) {
			continue
		}
		if !matchesSubjectNamespace(subj, opts.SubjectNamespace) {
			continue
		}
		if !matchesSubjectName(subj.Name, opts.SubjectName) {
			continue
		}
		if len(perms) == 0 {
			continue
		}
		permsCopy := append([]model.Permission(nil), perms...)
		sort.Slice(permsCopy, func(i, j int) bool {
			return permsCopy[i].String() < permsCopy[j].String()
		})
		extraOut = append(extraOut, subjectPermissions{
			Subject:     subj,
			Permissions: permsCopy,
		})
	}

	subjectsMissing := make([]model.SubjectKey, 0, len(d.Missing))
	for s := range d.Missing {
		subjectsMissing = append(subjectsMissing, s)
	}
	sort.Slice(subjectsMissing, func(i, j int) bool {
		return subjectsMissing[i].String() < subjectsMissing[j].String()
	})

	for _, subj := range subjectsMissing {
		perms := d.Missing[subj]
		if opts.IgnoreSystem && isSystemSubject(subj) {
			continue
		}
		if !matchesSubjectKind(subj, opts.SubjectKind) {
			continue
		}
		if !matchesSubjectNamespace(subj, opts.SubjectNamespace) {
			continue
		}
		if !matchesSubjectName(subj.Name, opts.SubjectName) {
			continue
		}
		if len(perms) == 0 {
			continue
		}
		permsCopy := append([]model.Permission(nil), perms...)
		sort.Slice(permsCopy, func(i, j int) bool {
			return permsCopy[i].String() < permsCopy[j].String()
		})
		missingOut = append(missingOut, subjectPermissions{
			Subject:     subj,
			Permissions: permsCopy,
		})
	}

	return extraOut, missingOut
}

func filterNetPolDriftToJSON(d diff.NetPolDrift, opts Options) netPolDriftJSON {
	j := netPolDriftJSON{}

	// extra / missing controlled by drift-type
	if opts.DriftType == "extra" || opts.DriftType == "both" {
		for _, ref := range d.Extra {
			if opts.IgnoreSystem && isSystemNamespace(ref.Namespace) {
				continue
			}
			j.Extra = append(j.Extra, ref)
		}
	}
	if opts.DriftType == "missing" || opts.DriftType == "both" {
		for _, ref := range d.Missing {
			if opts.IgnoreSystem && isSystemNamespace(ref.Namespace) {
				continue
			}
			j.Missing = append(j.Missing, ref)
		}
	}
	// "changed" is always interesting, independent of extra/missing
	for _, ch := range d.Changed {
		if opts.IgnoreSystem && isSystemNamespace(ch.Namespace) {
			continue
		}
		j.Changed = append(j.Changed, ch)
	}

	return j
}

func psaDriftToJSON(d diff.PSADrift, opts Options) psaDriftJSON {
	out := psaDriftJSON{}

	addFiltered := func(dst *[]model.PSADriftEntry, src []model.PSADriftEntry) {
		for _, e := range src {
			if opts.IgnoreSystem && isSystemNamespace(e.Namespace) {
				continue
			}
			*dst = append(*dst, e)
		}
		// Stable ordering for deterministic output
		sort.Slice(*dst, func(i, j int) bool {
			return (*dst)[i].Namespace < (*dst)[j].Namespace
		})
	}

	// Honor drift-type like RBAC (extra/missing/both)
	switch opts.DriftType {
	case "extra":
		addFiltered(&out.Extra, d.Extra)
	case "missing":
		addFiltered(&out.Missing, d.Missing)
	case "both":
		addFiltered(&out.Extra, d.Extra)
		addFiltered(&out.Missing, d.Missing)
	default:
		// normalizeDriftType() should prevent this, but keep safe default
		addFiltered(&out.Extra, d.Extra)
	}

	return out
}

func printJSONReport(
	modeLabel string,
	opts Options,
	rbacDrift diff.RBACDrift,
	netpolDrift diff.NetPolDrift,
	psaDrift diff.PSADrift,
) error {
	extra, missing := filterRBACDriftToSlices(rbacDrift, opts)

	rbacJSON := rbacDriftJSON{}
	switch opts.DriftType {
	case "extra":
		rbacJSON.Extra = extra
	case "missing":
		rbacJSON.Missing = missing
	case "both":
		rbacJSON.Extra = extra
		rbacJSON.Missing = missing
	}

	netpolJSON := filterNetPolDriftToJSON(netpolDrift, opts)

	// ✅ PSA now respects drift-type via psaDriftToJSON
	psaJSON := psaDriftToJSON(psaDrift, opts)

	report := driftReportJSON{
		Mode:             modeLabel,
		DriftType:        opts.DriftType,
		IgnoreSystem:     opts.IgnoreSystem,
		SubjectKind:      opts.SubjectKind,
		SubjectName:      opts.SubjectName,
		SubjectNamespace: opts.SubjectNamespace,
		RBAC:             rbacJSON,
		NetworkPolicy:    netpolJSON,
		PSA:              psaJSON,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// -----------------------------------------------------------------------------
// Human-readable output
// -----------------------------------------------------------------------------

func printHumanReport(
	modeLabel string,
	opts Options,
	rbacDrift diff.RBACDrift,
	netpolDrift diff.NetPolDrift,
	psaDrift diff.PSADrift,
) {
	fmt.Printf("Mode: %s\n", modeLabel)
	if opts.BaselineDir != "" {
		fmt.Printf("Baseline YAML dir: %s\n", opts.BaselineDir)
	}
	if opts.Kubeconfig != "" {
		fmt.Printf("Live kubeconfig: %s\n", opts.Kubeconfig)
	}
	if opts.KubeconfigA != "" || opts.KubeconfigB != "" {
		if opts.KubeconfigA != "" {
			fmt.Printf("Cluster A kubeconfig: %s\n", opts.KubeconfigA)
		}
		if opts.KubeconfigB != "" {
			fmt.Printf("Cluster B kubeconfig: %s\n", opts.KubeconfigB)
		}
	}
	fmt.Printf("Drift type: %s\n", opts.DriftType)
	fmt.Printf("Ignore system: %v\n", opts.IgnoreSystem)
	if strings.TrimSpace(opts.SubjectKind) != "" && strings.ToLower(opts.SubjectKind) != "all" {
		fmt.Printf("Subject kind filter: %s\n", opts.SubjectKind)
	}
	if strings.TrimSpace(opts.SubjectName) != "" {
		fmt.Printf("Subject name filter: %s\n", opts.SubjectName)
	}
	if strings.TrimSpace(opts.SubjectNamespace) != "" {
		fmt.Printf("Subject namespace filter: %s\n", opts.SubjectNamespace)
	}

	fmt.Println()
	printHumanRBAC(opts, rbacDrift)
	fmt.Println()
	printHumanNetPol(opts, netpolDrift)
	fmt.Println()
	printHumanPSA(opts, psaDrift)
}

func printHumanRBAC(opts Options, rbacDrift diff.RBACDrift) {
	extra, missing := filterRBACDriftToSlices(rbacDrift, opts)

	hasExtra := len(extra) > 0 && (opts.DriftType == "extra" || opts.DriftType == "both")
	hasMissing := len(missing) > 0 && (opts.DriftType == "missing" || opts.DriftType == "both")

	if !hasExtra && !hasMissing {
		fmt.Println(" No RBAC drift detected matching the current filters.")
		return
	}

	if hasExtra {
		fmt.Printf(" RBAC drift: subjects with extra permissions in live vs baseline (%d subjects):\n", len(extra))
		for _, sp := range extra {
			fmt.Printf("\nSubject: %s\n", sp.Subject.String())
			fmt.Println("  Extra permissions vs baseline:")
			for _, p := range sp.Permissions {
				fmt.Printf("    - %s\n", p.String())
			}
		}
		fmt.Println()
	} else if opts.DriftType == "extra" {
		fmt.Println(" No extra RBAC permissions detected matching the current filters.")
	}

	if hasMissing {
		fmt.Printf("  RBAC drift: subjects with missing permissions in live vs baseline (%d subjects):\n", len(missing))
		for _, sp := range missing {
			fmt.Printf("\nSubject: %s\n", sp.Subject.String())
			fmt.Println("  Missing permissions vs baseline:")
			for _, p := range sp.Permissions {
				fmt.Printf("    - %s\n", p.String())
			}
		}
	} else if opts.DriftType == "missing" {
		fmt.Println(" No missing RBAC permissions detected matching the current filters.")
	}
}

func printHumanNetPol(opts Options, netpolDrift diff.NetPolDrift) {
	j := filterNetPolDriftToJSON(netpolDrift, opts)

	hasExtra := len(j.Extra) > 0
	hasMissing := len(j.Missing) > 0
	hasChanged := len(j.Changed) > 0

	if !hasExtra && !hasMissing && !hasChanged {
		fmt.Println(" No NetworkPolicy drift detected matching the current filters.")
		return
	}

	fmt.Println(" NetworkPolicy drift detected:")

	if hasMissing {
		fmt.Printf("\nPolicies present in baseline but missing in live (%d):\n", len(j.Missing))
		for _, ref := range j.Missing {
			fmt.Printf("  - %s\n", ref.String())
		}
	} else if opts.DriftType == "missing" || opts.DriftType == "both" {
		fmt.Println("\nNo NetworkPolicies missing in live vs baseline (after filters).")
	}

	if hasExtra {
		fmt.Printf("\nPolicies present in live but not in baseline (%d):\n", len(j.Extra))
		for _, ref := range j.Extra {
			fmt.Printf("  - %s\n", ref.String())
		}
	} else if opts.DriftType == "extra" || opts.DriftType == "both" {
		fmt.Println("\nNo extra NetworkPolicies in live vs baseline (after filters).")
	}

	if hasChanged {
		fmt.Printf("\nPolicies whose spec changed between baseline and live (%d):\n", len(j.Changed))
		for _, ch := range j.Changed {
			fmt.Printf(
				"  - %s/%s (types: A=%v, B=%v; ingress: A=%d, B=%d; egress: A=%d, B=%d)\n",
				ch.Namespace, ch.Name,
				ch.Baseline.PolicyTypes, ch.Live.PolicyTypes,
				ch.Baseline.IngressCount, ch.Live.IngressCount,
				ch.Baseline.EgressCount, ch.Live.EgressCount,
			)
		}
	}
}

func printHumanPSA(opts Options, psaDrift diff.PSADrift) {
	j := psaDriftToJSON(psaDrift, opts)

	hasExtra := len(j.Extra) > 0 && (opts.DriftType == "extra" || opts.DriftType == "both")
	hasMissing := len(j.Missing) > 0 && (opts.DriftType == "missing" || opts.DriftType == "both")

	if !hasExtra && !hasMissing {
		fmt.Println(" No Pod Security Admission (PSA) drift detected matching the current filters.")
		return
	}

	fmt.Println(" Pod Security Admission (PSA) drift detected:")

	if hasExtra {
		fmt.Printf("\nNamespaces weaker in live vs baseline (%d):\n", len(j.Extra))
		for _, e := range j.Extra {
			fmt.Printf(" - Namespace %s: baseline=%s, live=%s → %s\n",
				e.Namespace, e.Baseline, e.Live, e.DriftType)
		}
	} else if opts.DriftType == "extra" {
		fmt.Println("\nNo weaker (extra-risk) PSA drift detected (after filters).")
	}

	if hasMissing {
		fmt.Printf("\nNamespaces stricter in live vs baseline (%d):\n", len(j.Missing))
		for _, e := range j.Missing {
			fmt.Printf(" - Namespace %s: baseline=%s, live=%s → %s\n",
				e.Namespace, e.Baseline, e.Live, e.DriftType)
		}
	} else if opts.DriftType == "missing" {
		fmt.Println("\nNo stricter (missing-risk) PSA drift detected (after filters).")
	}
}
