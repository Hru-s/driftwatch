package diff

import (
	"sort"

	"github.com/Hru-s/driftwatch/internal/model"
)

// PSADrift is the aggregated PSA drift result.
type PSADrift struct {
	Entries []model.PSADriftEntry
}

// DiffPSA compares baseline vs live NamespacePSA slices.
func DiffPSA(baseline, live []model.NamespacePSA) PSADrift {
	bMap := make(map[string]model.NamespacePSA, len(baseline))
	lMap := make(map[string]model.NamespacePSA, len(live))

	for _, b := range baseline {
		bMap[b.Namespace] = b
	}
	for _, l := range live {
		lMap[l.Namespace] = l
	}

	var entries []model.PSADriftEntry

	// Baseline-driven: missing + weaker/stronger.
	for ns, b := range bMap {
		l, ok := lMap[ns]
		if !ok {
			entries = append(entries, model.PSADriftEntry{
				Namespace: ns,
				Baseline:  b.Enforce,
				DriftType: "missing", // namespace/PSA not present in live
			})
			continue
		}

		if b.Enforce != l.Enforce {
			entries = append(entries, model.PSADriftEntry{
				Namespace: ns,
				Baseline:  b.Enforce,
				Live:      l.Enforce,
				DriftType: classifyPSADrift(b.Enforce, l.Enforce),
			})
		}
	}

	// Namespaces only in live.
	for ns, l := range lMap {
		if _, ok := bMap[ns]; !ok {
			entries = append(entries, model.PSADriftEntry{
				Namespace: ns,
				Live:      l.Enforce,
				DriftType: "extra",
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Namespace < entries[j].Namespace
	})

	return PSADrift{Entries: entries}
}

func classifyPSADrift(base, live model.PSALevel) string {
	order := map[model.PSALevel]int{
		model.PSALevelPrivileged: 1,
		model.PSALevelBaseline:   2,
		model.PSALevelRestricted: 3,
	}

	b := order[base]
	l := order[live]

	if b == 0 || l == 0 {
		return "different"
	}
	if l < b {
		return "weaker" // less restrictive than baseline
	}
	if l > b {
		return "stronger"
	}
	return "different"
}
