package diff

import (
	"sort"

	"github.com/Hru-s/driftwatch/internal/model"
)

type NetPolDrift struct {
	Missing []model.NetPolRef    `json:"missing"`
	Extra   []model.NetPolRef    `json:"extra"`
	Changed []model.NetPolChange `json:"changed"`
}

func DiffNetworkPolicies(baseline, live *model.NetPolSnapshot) NetPolDrift {
	result := NetPolDrift{}

	keys := map[string]struct{}{}
	for k := range baseline.Items {
		keys[k] = struct{}{}
	}
	for k := range live.Items {
		keys[k] = struct{}{}
	}

	for key := range keys {
		base, okBase := baseline.Items[key]
		liveItem, okLive := live.Items[key]

		switch {
		case okBase && !okLive:
			result.Missing = append(result.Missing, model.NetPolRef{
				Namespace: base.Namespace,
				Name:      base.Name,
			})
		case !okBase && okLive:
			result.Extra = append(result.Extra, model.NetPolRef{
				Namespace: liveItem.Namespace,
				Name:      liveItem.Name,
			})
		case okBase && okLive:
			if base.SpecHash != liveItem.SpecHash {
				result.Changed = append(result.Changed, model.NetPolChange{
					Namespace: base.Namespace,
					Name:      base.Name,
					Baseline:  base,
					Live:      liveItem,
				})
			}
		}
	}

	sort.Slice(result.Missing, func(i, j int) bool {
		if result.Missing[i].Namespace == result.Missing[j].Namespace {
			return result.Missing[i].Name < result.Missing[j].Name
		}
		return result.Missing[i].Namespace < result.Missing[j].Namespace
	})
	sort.Slice(result.Extra, func(i, j int) bool {
		if result.Extra[i].Namespace == result.Extra[j].Namespace {
			return result.Extra[i].Name < result.Extra[j].Name
		}
		return result.Extra[i].Namespace < result.Extra[j].Namespace
	})
	sort.Slice(result.Changed, func(i, j int) bool {
		if result.Changed[i].Namespace == result.Changed[j].Namespace {
			return result.Changed[i].Name < result.Changed[j].Name
		}
		return result.Changed[i].Namespace < result.Changed[j].Namespace
	})

	return result
}
