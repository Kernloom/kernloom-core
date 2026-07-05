// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package projector

import (
	"fmt"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/kliq/baseline"
)

const KLShieldAdapterID = "kernloom.adapter.klshield"

type KLShieldProjector struct{}

func (KLShieldProjector) Project(raw baseline.AdapterSignal) ([]baseline.Sample, error) {
	if strings.TrimSpace(raw.AdapterID) != KLShieldAdapterID {
		return nil, fmt.Errorf("klshield projector received adapter_id %q", raw.AdapterID)
	}
	entity := strings.TrimSpace(raw.Labels["entity"])
	if entity == "" {
		entity = strings.TrimSpace(raw.Labels["source"])
	}
	if entity == "" {
		return nil, fmt.Errorf("klshield signal requires entity label")
	}
	observedAt := raw.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	samples := make([]baseline.Sample, 0, len(raw.Metrics))
	for metric, value := range raw.Metrics {
		metric = strings.TrimSpace(metric)
		if metric == "" {
			continue
		}
		samples = append(samples, baseline.Sample{
			Key: baseline.Key{
				View:   baseline.ViewEntity,
				Entity: "klshield:" + entity,
			},
			Metric:     metric,
			Value:      value,
			ObservedAt: observedAt.UTC(),
		})
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("klshield signal requires at least one metric")
	}
	return samples, nil
}
