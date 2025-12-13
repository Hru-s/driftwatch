package diff

import (
	"sort"

	"github.com/Hru-s/driftwatch/internal/model"
)

// PSADrift is the aggregated PSA drift result.
// Extra:   PSA posture in right/live is weaker (less restrictive) than left/baseline,
//
//	OR namespaces only present in live.
//
// Missing: PSA posture in right/live is stronger (more restrictive) than left/baseline,
//
//	OR namespaces present in baseline but missing in live.
type PSADrift struct {
	Extra   []model.PSADriftEntry
	Missing []model.PSADriftEntry
}

// DiffPSA compares baseline vs live NamespacePSA slices and buckets drift into Extra/Missing.
// Semantics (direction):
//   - Extra:   live is weaker / more permissive than baseline (security regression)
//   - Missing: live is stronger / more restrictive than baseline (security tightening drift)
func DiffPSA(baseline, live []model.NamespacePSA) PSADrift {
	bMap := make(map[string]model.NamespacePSA, len(baseline))
	lMap := make(map[string]model.NamespacePSA, len(live))

	for _, b := range baseline {
		bMap[b.Namespace] = b
	}
	for _, l := range live {
		lMap[l.Namespace] = l
	}

	var extra []model.PSADriftEntry
	var missing []model.PSADriftEntry

	// Baseline-driven: namespaces missing in live + posture changes.
	for ns, b := range bMap {
		l, ok := lMap[ns]
		if !ok {
			// Namespace/PSA entry present in baseline but missing in live.
			missing = append(missing, model.PSADriftEntry{
				Namespace: ns,
				Baseline:  b.Enforce,
				DriftType: "missing",
			})
			continue
		}

		if b.Enforce != l.Enforce {
			dir, label := classifyPSADirection(b.Enforce, l.Enforce)

			e := model.PSADriftEntry{
				Namespace: ns,
				Baseline:  b.Enforce,
				Live:      l.Enforce,
				DriftType: label, // "weaker" | "stronger" | "different"
			}

			switch dir {
			case "extra":
				extra = append(extra, e)
			case "missing":
				missing = append(missing, e)
			default:
				// If direction can't be determined, bucket to Extra by default
				// (conservative: treat as potential regression).
				extra = append(extra, e)
			}
		}
	}

	// Namespaces only in live.
	for ns, l := range lMap {
		if _, ok := bMap[ns]; !ok {
			extra = append(extra, model.PSADriftEntry{
				Namespace: ns,
				Live:      l.Enforce,
				DriftType: "extra",
			})
		}
	}

	// Deterministic ordering
	sort.Slice(extra, func(i, j int) bool { return extra[i].Namespace < extra[j].Namespace })
	sort.Slice(missing, func(i, j int) bool { return missing[i].Namespace < missing[j].Namespace })

	return PSADrift{Extra: extra, Missing: missing}
}

func classifyPSADirection(base, live model.PSALevel) (direction string, label string) {
	// Higher = more restrictive
	b := psaRank(base)
	l := psaRank(live)

	// If ranks are comparable:
	if l < b {
		return "extra", "weaker" // live less restrictive than baseline
	}
	if l > b {
		return "missing", "stronger" // live more restrictive than baseline
	}

	// Same rank but different value (unknown/custom strings)
	// Direction is ambiguous; still report drift.
	return "extra", "different"
}

func psaRank(level model.PSALevel) int {
	switch level {
	case model.PSALevelPrivileged:
		return 1
	case model.PSALevelBaseline:
		return 2
	case model.PSALevelRestricted:
		return 3
	default:
		// Treat missing/unknown as weakest.
		// This makes baseline=restricted, live="" classify as weaker (extra-risk).
		return 0
	}
}
