package hunter

import (
	"context"
	"fmt"

	"github.com/fatih/semgroup"
	"github.com/pelletier/go-toml/v2"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func normalizeFindings(goFindings []report.Finding) []Finding {
	var findings []Finding
	for _, f := range goFindings {
		findings = append(findings, Finding{
			DetectorType: f.RuleID,
			Line:         f.StartLine,
			Secret:       f.Secret,
			File:         f.File,
			Verified:     false,
		})
	}
	return findings
}

type GitLeaks struct {
	ctx context.Context
}

func NewGitLeaks() Hunter {
	ctx := context.Background()
	return &GitLeaks{ctx: ctx}
}

func (g *GitLeaks) Hunt(path string) ([]Finding, error) {
	var vc config.ViperConfig
	if err := toml.Unmarshal([]byte(config.DefaultConfig), &vc); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	cfg, err := vc.Translate()
	if err != nil {
		return nil, fmt.Errorf("translate config: %w", err)
	}

	// Build detector – same defaults as cmd/directory.go uses via cobra flags.
	detector := detect.NewDetectorContext(g.ctx, cfg)
	detector.MaxDecodeDepth = 5  // --max-decode-depth default
	detector.MaxArchiveDepth = 0 // --max-archive-depth default
	detector.FollowSymlinks = false
	detector.Verbose = false
	detector.Redact = 0
	detector.MaxTargetMegaBytes = 0
	detector.IgnoreGitleaksAllow = false

	filesSource := &sources.Files{
		Config:          &cfg,
		FollowSymlinks:  detector.FollowSymlinks,
		MaxFileSize:     detector.MaxTargetMegaBytes * 1_000_000,
		Path:            path,
		Sema:            semgroup.NewGroup(g.ctx, 40),
		MaxArchiveDepth: detector.MaxArchiveDepth,
	}

	findings, err := detector.DetectSource(g.ctx, filesSource)
	if err != nil {
		return normalizeFindings(findings), fmt.Errorf("DetectSource: %w", err)
	}
	return normalizeFindings(findings), nil
}