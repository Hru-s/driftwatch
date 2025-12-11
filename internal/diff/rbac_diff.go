package diff

import "github.com/Hru-s/driftwatch/internal/model"

type RBACDrift struct {
	Extra   map[model.SubjectKey][]model.Permission
	Missing map[model.SubjectKey][]model.Permission
}

// DiffRBAC returns permissions that live has extra vs baseline, and ones
// that are missing in live compared to baseline.
func DiffRBAC(baseline, live *model.RBACSnapshot) RBACDrift {
	result := RBACDrift{
		Extra:   make(map[model.SubjectKey][]model.Permission),
		Missing: make(map[model.SubjectKey][]model.Permission),
	}

	// union of subjects
	allSubjects := map[model.SubjectKey]struct{}{}
	for s := range baseline.Subjects {
		allSubjects[s] = struct{}{}
	}
	for s := range live.Subjects {
		allSubjects[s] = struct{}{}
	}

	for subj := range allSubjects {
		basePerms := baseline.Subjects[subj]
		livePerms := live.Subjects[subj]

		// Extra = live - baseline
		if len(livePerms) > 0 {
			extras := make([]model.Permission, 0)
			for p := range livePerms {
				if _, ok := basePerms[p]; !ok {
					extras = append(extras, p)
				}
			}
			if len(extras) > 0 {
				result.Extra[subj] = extras
			}
		}

		// Missing = baseline - live
		if len(basePerms) > 0 {
			missing := make([]model.Permission, 0)
			for p := range basePerms {
				if _, ok := livePerms[p]; !ok {
					missing = append(missing, p)
				}
			}
			if len(missing) > 0 {
				result.Missing[subj] = missing
			}
		}
	}

	return result
}
