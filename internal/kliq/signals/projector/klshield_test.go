// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package projector

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom-core/internal/kliq/baseline"
)

func TestKLShieldProjectorEmitsEntitySamplesOnly(t *testing.T) {
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	samples, err := (KLShieldProjector{}).Project(baseline.AdapterSignal{
		AdapterID:  KLShieldAdapterID,
		SignalType: "runtime_action_state",
		Labels:     map[string]string{"source": "10.0.0.1"},
		Metrics:    map[string]float64{"packet_rate": 1200},
		ObservedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("expected one sample, got %#v", samples)
	}
	if samples[0].Key.View != baseline.ViewEntity || samples[0].Key.Entity != "klshield:10.0.0.1" || samples[0].Metric != "packet_rate" {
		t.Fatalf("unexpected sample %#v", samples[0])
	}
}

func TestKLShieldProjectorRejectsOtherAdapters(t *testing.T) {
	_, err := (KLShieldProjector{}).Project(baseline.AdapterSignal{
		AdapterID: "kernloom.adapter.other",
		Labels:    map[string]string{"source": "10.0.0.1"},
		Metrics:   map[string]float64{"packet_rate": 1},
	})
	if err == nil {
		t.Fatal("expected adapter mismatch")
	}
}
