package cleaner

import "github.com/FishLeaks/FishLeaks/pkg/hunter"

type textCleaner struct {
}

func NewTextCleaner() BaseCleaner {
	return &textCleaner{}
}

func (c *textCleaner) Clean(finding hunter.Finding) error {
	return sedSubstitute(finding.File, finding.Secret, "REDACTED")		
}

