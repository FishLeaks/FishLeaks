package cleaner

import "github.com/FishLeaks/FishLeaks/pkg/hunter"

type BaseCleaner interface {
	Clean(finding hunter.Finding) error
}
