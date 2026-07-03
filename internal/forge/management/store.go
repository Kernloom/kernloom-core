// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package management

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
)

var ErrNotFound = errors.New("kliq management record not found")

type Store interface {
	CreateEnrollmentToken(ctx context.Context, token domain.KLIQEnrollmentToken, secret string) error
	UseEnrollmentToken(ctx context.Context, secret, environment, stage, scope string, usedAt time.Time) (domain.KLIQEnrollmentToken, error)
	Register(ctx context.Context, registration domain.KLIQRegistration) error
	Registration(ctx context.Context, kliqID string) (domain.KLIQRegistration, error)
	SaveAssignment(ctx context.Context, kliqID string, version int64, envelope signing.SignedEnvelope) error
	LatestAssignment(ctx context.Context, kliqID string) (signing.SignedEnvelope, error)
	SaveHeartbeat(ctx context.Context, heartbeat domain.KLIQHeartbeat) error
	SaveStatusReport(ctx context.Context, report domain.KLIQStatusReport) error
	StatusReport(ctx context.Context, kliqID string) (domain.KLIQStatusReport, error)
}

type MemoryStore struct {
	mu            sync.Mutex
	tokensByHash  map[string]domain.KLIQEnrollmentToken
	registrations map[string]domain.KLIQRegistration
	assignments   map[string]assignmentRecord
	heartbeats    map[string]domain.KLIQHeartbeat
	statusReports map[string]domain.KLIQStatusReport
}

type assignmentRecord struct {
	Version  int64
	Envelope signing.SignedEnvelope
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tokensByHash:  map[string]domain.KLIQEnrollmentToken{},
		registrations: map[string]domain.KLIQRegistration{},
		assignments:   map[string]assignmentRecord{},
		heartbeats:    map[string]domain.KLIQHeartbeat{},
		statusReports: map[string]domain.KLIQStatusReport{},
	}
}

func NewEnrollmentSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "kliq_enroll_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func TokenSHA256(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *MemoryStore) CreateEnrollmentToken(_ context.Context, token domain.KLIQEnrollmentToken, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token.TokenID == "" || secret == "" {
		return fmt.Errorf("enrollment token id and secret are required")
	}
	token.TokenSHA256 = TokenSHA256(secret)
	if token.CreatedAt.IsZero() {
		token.CreatedAt = time.Now().UTC()
	}
	s.tokensByHash[token.TokenSHA256] = token
	return nil
}

func (s *MemoryStore) UseEnrollmentToken(_ context.Context, secret, environment, stage, scope string, usedAt time.Time) (domain.KLIQEnrollmentToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.tokensByHash[TokenSHA256(secret)]
	if !ok {
		return domain.KLIQEnrollmentToken{}, ErrNotFound
	}
	if !token.ExpiresAt.IsZero() && !usedAt.UTC().Before(token.ExpiresAt.UTC()) {
		return domain.KLIQEnrollmentToken{}, fmt.Errorf("enrollment token expired")
	}
	if !token.UsedAt.IsZero() {
		return domain.KLIQEnrollmentToken{}, fmt.Errorf("enrollment token already used")
	}
	if token.Environment != "" && token.Environment != environment {
		return domain.KLIQEnrollmentToken{}, fmt.Errorf("enrollment token environment mismatch")
	}
	if token.Stage != "" && token.Stage != stage {
		return domain.KLIQEnrollmentToken{}, fmt.Errorf("enrollment token stage mismatch")
	}
	if token.Scope != "" && token.Scope != scope {
		return domain.KLIQEnrollmentToken{}, fmt.Errorf("enrollment token scope mismatch")
	}
	token.UsedAt = usedAt.UTC()
	s.tokensByHash[token.TokenSHA256] = token
	return token, nil
}

func (s *MemoryStore) Register(_ context.Context, registration domain.KLIQRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if registration.KLIQID == "" {
		return fmt.Errorf("kliq registration requires kliq_id")
	}
	s.registrations[registration.KLIQID] = registration
	return nil
}

func (s *MemoryStore) Registration(_ context.Context, kliqID string) (domain.KLIQRegistration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	registration, ok := s.registrations[kliqID]
	if !ok {
		return domain.KLIQRegistration{}, ErrNotFound
	}
	return registration, nil
}

func (s *MemoryStore) SaveAssignment(_ context.Context, kliqID string, version int64, envelope signing.SignedEnvelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if kliqID == "" || version <= 0 {
		return fmt.Errorf("assignment requires kliq_id and positive assignment_version")
	}
	existing, ok := s.assignments[kliqID]
	if ok && version < existing.Version {
		return fmt.Errorf("assignment version %d is older than existing version %d", version, existing.Version)
	}
	s.assignments[kliqID] = assignmentRecord{Version: version, Envelope: envelope}
	return nil
}

func (s *MemoryStore) LatestAssignment(_ context.Context, kliqID string) (signing.SignedEnvelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.assignments[kliqID]
	if !ok {
		return signing.SignedEnvelope{}, ErrNotFound
	}
	return record.Envelope, nil
}

func (s *MemoryStore) SaveHeartbeat(_ context.Context, heartbeat domain.KLIQHeartbeat) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if heartbeat.KLIQID == "" {
		return fmt.Errorf("heartbeat requires kliq_id")
	}
	s.heartbeats[heartbeat.KLIQID] = heartbeat
	return nil
}

func (s *MemoryStore) SaveStatusReport(_ context.Context, report domain.KLIQStatusReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if report.KLIQID == "" {
		return fmt.Errorf("status report requires kliq_id")
	}
	s.statusReports[report.KLIQID] = report
	return nil
}

func (s *MemoryStore) StatusReport(_ context.Context, kliqID string) (domain.KLIQStatusReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	report, ok := s.statusReports[kliqID]
	if !ok {
		return domain.KLIQStatusReport{}, ErrNotFound
	}
	return report, nil
}

func StableKLIQID(nodeID, environment, stage, scope string) string {
	sum := sha256.Sum256([]byte(nodeID + "\x00" + environment + "\x00" + stage + "\x00" + scope))
	return "kliq." + hex.EncodeToString(sum[:])[:16]
}
