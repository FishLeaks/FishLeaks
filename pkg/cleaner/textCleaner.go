package cleaner

import "github.com/FishLeaks/FishLeaks/pkg/hunter"

type textCleaner struct {
	findings []hunter.Finding
}

func NewTextCleaner() BaseCleaner {
	return &textCleaner{}
}

func (c *textCleaner) Clean(finding hunter.Finding) error {
	return sedSubstitute(finding.File, finding.Secret, "REDACTED")		
}

