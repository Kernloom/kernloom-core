// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package baseline

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestMedianMADEstimatorHandlesOutliersAndInsufficientSamples(t *testing.T) {
	estimator := MedianMADEstimator{}
	if _, _, ok := estimator.Estimate([]float64{1, 2, 3}); ok {
		t.Fatal("expected insufficient samples to be unknown")
	}
	center, spread, ok := estimator.Estimate([]float64{10, 10, 11, 12, 1000})
	if !ok {
		t.Fatal("expected estimate")
	}
	if center != 11 || spread != 1 {
		t.Fatalf("expected robust median/mad, got center=%f spread=%f", center, spread)
	}
}

func TestEngineLearnsFrozenVersionFromCleanWindow(t *testing.T) {
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	store := &memoryBaselineStore{}
	engine := Engine{Store: store, Now: func() time.Time { return now }}
	samples := []Sample{
		sample(10, now.Add(-5*time.Second)),
		sample(11, now.Add(-4*time.Second)),
		sample(12, now.Add(-3*time.Second)),
		sample(11, now.Add(-2*time.Second)),
		sample(10, now.Add(-time.Second)),
	}
	version, stats, learned, err := engine.LearnWindow(context.Background(), samples, 0.9, 0.01, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !learned || version.VersionID == "" || !version.PromotedAt.IsZero() || len(stats) != 1 {
		t.Fatalf("expected frozen non-promoted version and stats, got version=%#v stats=%#v learned=%t", version, stats, learned)
	}
}

func TestEngineRejectsInlinePromotion(t *testing.T) {
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	store := &memoryBaselineStore{}
	engine := Engine{Store: store, Now: func() time.Time { return now }}
	_, _, _, err := engine.LearnWindow(context.Background(), []Sample{
		sample(10, now.Add(-5*time.Second)),
		sample(11, now.Add(-4*time.Second)),
		sample(12, now.Add(-3*time.Second)),
		sample(11, now.Add(-2*time.Second)),
		sample(10, now.Add(-time.Second)),
	}, 0.9, 0.01, true, true)
	if err == nil {
		t.Fatal("expected inline promotion to be rejected")
	}
}

func TestDomainTermsStayOutOfBaselineEngine(t *testing.T) {
	root := filepath.Join("..", "baseline")
	forbidden := []string{"source", "klshield", "port", "route"}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := strings.ToLower(string(data))
		for _, word := range forbidden {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(word) + `\b`).MatchString(text) {
				t.Fatalf("baseline engine file %s contains forbidden domain term %q", path, word)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func sample(value float64, observedAt time.Time) Sample {
	return Sample{Key: Key{View: ViewEntity, Entity: "opaque-entity"}, Metric: "metric", Value: value, ObservedAt: observedAt}
}

type memoryBaselineStore struct {
	windows  []Window
	versions []VersionRef
	stats    []Stats
	events   []DeviationEvent
}

func (s *memoryBaselineStore) SaveBaselineWindow(_ context.Context, window Window) error {
	s.windows = append(s.windows, window)
	return nil
}

func (s *memoryBaselineStore) SaveBaselineVersion(_ context.Context, version VersionRef, stats []Stats) error {
	s.versions = append(s.versions, version)
	s.stats = append(s.stats, stats...)
	return nil
}

func (s *memoryBaselineStore) SaveBaselineDeviation(_ context.Context, event DeviationEvent) error {
	s.events = append(s.events, event)
	return nil
}
