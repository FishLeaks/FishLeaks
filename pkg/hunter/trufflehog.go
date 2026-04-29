package hunter

import (
	"fmt"
	"log"
	"sync"

	"github.com/go-logr/logr"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// collectingDispatcher receives ResultWithMetadata from the engine and
// stores them in a thread-safe slice.
type collectingDispatcher struct {
	mu       sync.Mutex
	findings []Finding
}

func (d *collectingDispatcher) Dispatch(_ context.Context, r detectors.ResultWithMetadata) error {
	f := Finding{
		DetectorType: r.DetectorType.String(),
		Line:         int(r.SourceMetadata.GetFilesystem().Line),
		Secret:       string(r.Raw),
		File:         r.SourceMetadata.GetFilesystem().File,
		Verified:     r.Verified,
	}

	d.mu.Lock()
	d.findings = append(d.findings, f)
	d.mu.Unlock()

	return nil
}

type TruffleHog struct {
	ctx context.Context
}

func NewTruffleHog() Hunter {
	// Use a no-op logger so trufflehog's internal info logs (concurrency,
	// source-manager, etc.) are silenced.
	ctx := context.WithLogger(context.Background(), logr.Discard())
	return &TruffleHog{ctx: ctx}
}

func (t *TruffleHog) Hunt(path string) ([]Finding, error) {
	disp := &collectingDispatcher{}

	// Build source manager – uses headless (local) API by default.
	sm := sources.NewManager(sources.WithSourceUnits())

	eng, err := engine.NewEngine(t.ctx, &engine.Config{
		SourceManager: sm,
		Dispatcher:    disp,
		// Mirror default CLI behaviour: verify secrets against live endpoints.
		Verify: true,
		// Report all result categories (verified, unverified, unknown).
		Results: map[string]struct{}{
			"verified":   {},
			"unverified": {},
			"unknown":    {},
		},
	})
	if err != nil {
		log.Fatalf("failed to create engine: %v", err)
	}

	eng.Start(t.ctx)

	fsConfig := sources.FilesystemConfig{
		Paths: []string{path},
	}

	if _, err := eng.ScanFileSystem(t.ctx, fsConfig); err != nil {
		return nil, fmt.Errorf("ScanFileSystem error: %v", err)
	}

	if err := eng.Finish(t.ctx); err != nil {
		log.Printf("engine finish warning: %v", err)
	}

	return disp.findings, nil
}
