// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package baseline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const ViewEntity = "entity"

type Key struct {
	View   string `json:"view"`
	Entity string `json:"entity"`
}

type Sample struct {
	Key        Key       `json:"key"`
	Metric     string    `json:"metric"`
	Value      float64   `json:"value"`
	ObservedAt time.Time `json:"observed_at"`
}

type AdapterSignal struct {
	SignalID   string             `json:"signal_id,omitempty"`
	AdapterID  string             `json:"adapter_id"`
	SignalType string             `json:"signal_type"`
	Labels     map[string]string  `json:"labels,omitempty"`
	Metrics    map[string]float64 `json:"metrics,omitempty"`
	ObservedAt time.Time          `json:"observed_at"`
}

type Estimator interface {
	Estimate(samples []float64) (center float64, spread float64, ok bool)
}

type SignalProjector interface {
	Project(raw AdapterSignal) ([]Sample, error)
}

type VersionRef struct {
	VersionID  string    `json:"version_id"`
	View       string    `json:"view"`
	Entity     string    `json:"entity"`
	CreatedAt  time.Time `json:"created_at"`
	PromotedAt time.Time `json:"promoted_at,omitempty"`
}

type Stats struct {
	VersionID   string    `json:"version_id"`
	Key         Key       `json:"key"`
	Metric      string    `json:"metric"`
	Center      float64   `json:"center"`
	Spread      float64   `json:"spread"`
	SampleCount int       `json:"sample_count"`
	FrozenAt    time.Time `json:"frozen_at"`
}

type Window struct {
	WindowID        string    `json:"window_id"`
	Key             Key       `json:"key"`
	Metric          string    `json:"metric"`
	StartedAt       time.Time `json:"started_at"`
	EndedAt         time.Time `json:"ended_at"`
	SampleCount     int       `json:"sample_count"`
	Confidence      float64   `json:"confidence"`
	Clean           bool      `json:"clean"`
	AnomalyFraction float64   `json:"anomaly_fraction"`
}

type DeviationEvent struct {
	EventID     string    `json:"event_id"`
	VersionID   string    `json:"version_id"`
	Key         Key       `json:"key"`
	Metric      string    `json:"metric"`
	Value       float64   `json:"value"`
	Center      float64   `json:"center"`
	Spread      float64   `json:"spread"`
	Score       float64   `json:"score"`
	ObservedAt  time.Time `json:"observed_at"`
	EmittedAt   time.Time `json:"emitted_at"`
	Reason      string    `json:"reason"`
	Confidence  float64   `json:"confidence"`
	RiskRecipe  string    `json:"risk_recipe,omitempty"`
	PolicyScope string    `json:"policy_scope,omitempty"`
}

type Reference interface {
	ActiveBaselineVersion(ctx context.Context, view, entity string) (VersionRef, bool, error)
	BaselineStats(ctx context.Context, versionID, metric string) (Stats, error)
}

type Store interface {
	SaveBaselineWindow(ctx context.Context, window Window) error
	SaveBaselineVersion(ctx context.Context, version VersionRef, stats []Stats, promote bool) error
	SaveBaselineDeviation(ctx context.Context, event DeviationEvent) error
}

type Engine struct {
	Store                   Store
	Estimator               Estimator
	Now                     func() time.Time
	MinSamples              int
	MinConfidence           float64
	MaxCleanAnomalyFraction float64
}

func (e Engine) LearnWindow(ctx context.Context, samples []Sample, confidence, anomalyFraction float64, clean bool, promote bool) (VersionRef, []Stats, bool, error) {
	if len(samples) == 0 {
		return VersionRef{}, nil, false, nil
	}
	if e.Store == nil {
		return VersionRef{}, nil, false, fmt.Errorf("baseline engine requires store")
	}
	estimator := e.Estimator
	if estimator == nil {
		estimator = MedianMADEstimator{}
	}
	minSamples := e.MinSamples
	if minSamples == 0 {
		minSamples = 5
	}
	minConfidence := e.MinConfidence
	if minConfidence == 0 {
		minConfidence = 0.70
	}
	maxAnomalyFraction := e.MaxCleanAnomalyFraction
	if maxAnomalyFraction == 0 {
		maxAnomalyFraction = 0.10
	}
	now := e.now()
	key := samples[0].Key
	metric := samples[0].Metric
	window := Window{
		WindowID:        "baseline_window." + shortHash(windowIdentity(samples, now)),
		Key:             key,
		Metric:          metric,
		StartedAt:       samples[0].ObservedAt.UTC(),
		EndedAt:         samples[len(samples)-1].ObservedAt.UTC(),
		SampleCount:     len(samples),
		Confidence:      confidence,
		Clean:           clean,
		AnomalyFraction: anomalyFraction,
	}
	if err := e.Store.SaveBaselineWindow(ctx, window); err != nil {
		return VersionRef{}, nil, false, err
	}
	if !clean || len(samples) < minSamples || confidence < minConfidence || anomalyFraction > maxAnomalyFraction {
		return VersionRef{}, nil, false, nil
	}
	values := make([]float64, 0, len(samples))
	for _, sample := range samples {
		if sample.Key != key || sample.Metric != metric {
			return VersionRef{}, nil, false, fmt.Errorf("baseline window must contain one key and metric")
		}
		values = append(values, sample.Value)
	}
	center, spread, ok := estimator.Estimate(values)
	if !ok {
		return VersionRef{}, nil, false, nil
	}
	version := VersionRef{
		VersionID: "baseline_version." + shortHash(key.View+"\x00"+key.Entity+"\x00"+metric+"\x00"+now.Format(time.RFC3339Nano)),
		View:      key.View,
		Entity:    key.Entity,
		CreatedAt: now,
	}
	if promote {
		version.PromotedAt = now
	}
	stats := []Stats{{
		VersionID:   version.VersionID,
		Key:         key,
		Metric:      metric,
		Center:      center,
		Spread:      spread,
		SampleCount: len(values),
		FrozenAt:    now,
	}}
	if err := e.Store.SaveBaselineVersion(ctx, version, stats, promote); err != nil {
		return VersionRef{}, nil, false, err
	}
	return version, stats, true, nil
}

func EvaluateSample(sample Sample, stats Stats, now time.Time) (DeviationEvent, bool) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	spread := stats.Spread
	if spread <= 0 {
		spread = 1
	}
	score := math.Abs(sample.Value-stats.Center) / spread
	if score < 3 {
		return DeviationEvent{}, false
	}
	return DeviationEvent{
		EventID:    "baseline_deviation." + shortHash(stats.VersionID+"\x00"+sample.Metric+"\x00"+sample.ObservedAt.Format(time.RFC3339Nano)),
		VersionID:  stats.VersionID,
		Key:        sample.Key,
		Metric:     sample.Metric,
		Value:      sample.Value,
		Center:     stats.Center,
		Spread:     stats.Spread,
		Score:      score,
		ObservedAt: sample.ObservedAt.UTC(),
		EmittedAt:  now.UTC(),
		Reason:     "sample exceeds frozen baseline by Median+MAD threshold",
		Confidence: 0.80,
	}, true
}

func (e Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func windowIdentity(samples []Sample, now time.Time) string {
	var b strings.Builder
	for _, sample := range samples {
		fmt.Fprintf(&b, "%s\x00%s\x00%s\x00%f\x00%s\n", sample.Key.View, sample.Key.Entity, sample.Metric, sample.Value, sample.ObservedAt.UTC().Format(time.RFC3339Nano))
	}
	b.WriteString(now.UTC().Format(time.RFC3339Nano))
	return b.String()
}

type MedianMADEstimator struct {
	MinSamples int
}

func (e MedianMADEstimator) Estimate(samples []float64) (float64, float64, bool) {
	minSamples := e.MinSamples
	if minSamples == 0 {
		minSamples = 5
	}
	if len(samples) < minSamples {
		return 0, 0, false
	}
	values := append([]float64(nil), samples...)
	sort.Float64s(values)
	center := median(values)
	deviations := make([]float64, 0, len(values))
	for _, value := range values {
		deviations = append(deviations, math.Abs(value-center))
	}
	spread := median(deviations)
	if spread == 0 {
		spread = 1
	}
	return center, spread, true
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mid := len(values) / 2
	if len(values)%2 == 1 {
		return values[mid]
	}
	return (values[mid-1] + values[mid]) / 2
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}
