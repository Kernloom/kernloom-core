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

type auditActorContextKey struct{}
type auditMetadataContextKey struct{}

func WithAuditActor(ctx context.Context, actor string) context.Context {
	if actor == "" {
		return ctx
	}
	return context.WithValue(ctx, auditActorContextKey{}, actor)
}

func auditActor(ctx context.Context) string {
	if actor, ok := ctx.Value(auditActorContextKey{}).(string); ok {
		return actor
	}
	return ""
}

func WithAuditMetadata(ctx context.Context, metadata map[string]any) context.Context {
	if len(metadata) == 0 {
		return ctx
	}
	return context.WithValue(ctx, auditMetadataContextKey{}, metadata)
}

func auditMetadata(ctx context.Context, extra map[string]any) map[string]any {
	base, _ := ctx.Value(auditMetadataContextKey{}).(map[string]any)
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	merged := map[string]any{}
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extra {
		merged[key] = value
	}
	return merged
}

type Store interface {
	CreateEnrollmentToken(ctx context.Context, token domain.KLIQEnrollmentToken, secret string) error
	EnrollmentToken(ctx context.Context, tokenID string) (domain.KLIQEnrollmentToken, error)
	UseEnrollmentToken(ctx context.Context, secret, environment, stage, scope string, usedAt time.Time) (domain.KLIQEnrollmentToken, error)
	RevokeEnrollmentToken(ctx context.Context, tokenID, reason string, revokedAt time.Time) error
	Register(ctx context.Context, registration domain.KLIQRegistration) error
	Registration(ctx context.Context, kliqID string) (domain.KLIQRegistration, error)
	Identity(ctx context.Context, kliqID string) (domain.KLIQIdentity, error)
	RevokeKLIQ(ctx context.Context, kliqID, reason string, revokedAt time.Time) error
	SaveTrustBundle(ctx context.Context, bundle domain.TrustBundle) error
	TrustBundle(ctx context.Context, keyID string) (domain.TrustBundle, error)
	RevokeTrustBundle(ctx context.Context, keyID, reason string, revokedAt time.Time) error
	NextAssignmentVersion(ctx context.Context, kliqID string) (int64, error)
	SaveAssignment(ctx context.Context, kliqID string, version int64, envelope signing.SignedEnvelope) error
	LatestAssignment(ctx context.Context, kliqID string) (signing.SignedEnvelope, error)
	RevokeAssignment(ctx context.Context, kliqID string, version int64, reason string, revokedAt time.Time) error
	SaveHeartbeat(ctx context.Context, heartbeat domain.KLIQHeartbeat) error
	SaveStatusReport(ctx context.Context, report domain.KLIQStatusReport) error
	StatusReport(ctx context.Context, kliqID string) (domain.KLIQStatusReport, error)
	SaveAuditEvent(ctx context.Context, event domain.ManagementAuditEvent) error
	AuditEvents(ctx context.Context, targetType, targetID string) ([]domain.ManagementAuditEvent, error)
}

type MemoryStore struct {
	mu            sync.Mutex
	tokensByHash  map[string]domain.KLIQEnrollmentToken
	tokensByID    map[string]domain.KLIQEnrollmentToken
	registrations map[string]domain.KLIQRegistration
	identities    map[string]domain.KLIQIdentity
	assignments   map[string]assignmentRecord
	trustBundles  map[string]domain.TrustBundle
	revocations   map[string]domain.KLIQRevocation
	auditEvents   []domain.ManagementAuditEvent
	heartbeats    map[string]domain.KLIQHeartbeat
	statusReports map[string]domain.KLIQStatusReport
}

type assignmentRecord struct {
	Version       int64
	Envelope      signing.SignedEnvelope
	RevokedAt     time.Time
	RevokedReason string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tokensByHash:  map[string]domain.KLIQEnrollmentToken{},
		tokensByID:    map[string]domain.KLIQEnrollmentToken{},
		registrations: map[string]domain.KLIQRegistration{},
		identities:    map[string]domain.KLIQIdentity{},
		assignments:   map[string]assignmentRecord{},
		trustBundles:  map[string]domain.TrustBundle{},
		revocations:   map[string]domain.KLIQRevocation{},
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

func (s *MemoryStore) CreateEnrollmentToken(ctx context.Context, token domain.KLIQEnrollmentToken, secret string) error {
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
	s.tokensByID[token.TokenID] = token
	s.appendAuditLocked(domain.ManagementAuditEvent{
		EventType:   "enrollment_token_created",
		Actor:       auditActor(ctx),
		TargetType:  "kliq_enrollment_token",
		TargetID:    token.TokenID,
		Environment: token.Environment,
		Stage:       token.Stage,
		Scope:       token.Scope,
		CreatedAt:   token.CreatedAt,
	})
	return nil
}

func (s *MemoryStore) EnrollmentToken(_ context.Context, tokenID string) (domain.KLIQEnrollmentToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.tokensByID[tokenID]
	if !ok {
		return domain.KLIQEnrollmentToken{}, ErrNotFound
	}
	return token, nil
}

func (s *MemoryStore) UseEnrollmentToken(ctx context.Context, secret, environment, stage, scope string, usedAt time.Time) (domain.KLIQEnrollmentToken, error) {
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
	if !token.RevokedAt.IsZero() {
		return domain.KLIQEnrollmentToken{}, fmt.Errorf("enrollment token revoked")
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
	s.tokensByID[token.TokenID] = token
	s.appendAuditLocked(domain.ManagementAuditEvent{
		EventType:   "enrollment_token_used",
		Actor:       auditActor(ctx),
		TargetType:  "kliq_enrollment_token",
		TargetID:    token.TokenID,
		Environment: token.Environment,
		Stage:       token.Stage,
		Scope:       token.Scope,
		CreatedAt:   token.UsedAt,
	})
	return token, nil
}

func (s *MemoryStore) RevokeEnrollmentToken(ctx context.Context, tokenID, reason string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.tokensByID[tokenID]
	if !ok {
		return ErrNotFound
	}
	token.RevokedAt = revokedAt.UTC()
	token.RevokedReason = reason
	s.tokensByID[token.TokenID] = token
	s.tokensByHash[token.TokenSHA256] = token
	s.revocations["kliq_enrollment_token:"+tokenID] = domain.KLIQRevocation{
		RevocationID: "revocation." + shortHash("kliq_enrollment_token:"+tokenID+revokedAt.String()),
		TargetType:   "kliq_enrollment_token",
		TargetID:     tokenID,
		Reason:       reason,
		CreatedAt:    revokedAt.UTC(),
		CreatedBy:    auditActor(ctx),
	}
	s.appendAuditLocked(domain.ManagementAuditEvent{
		EventType:  "revocation",
		Actor:      auditActor(ctx),
		TargetType: "kliq_enrollment_token",
		TargetID:   tokenID,
		Metadata:   map[string]any{"reason": reason},
		CreatedAt:  revokedAt.UTC(),
	})
	return nil
}

func (s *MemoryStore) Register(ctx context.Context, registration domain.KLIQRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if registration.KLIQID == "" {
		return fmt.Errorf("kliq registration requires kliq_id")
	}
	if registration.Status == "" {
		registration.Status = "active"
	}
	if registration.Identity.IdentityID == "" {
		registration.Identity.IdentityID = "kliq_identity." + registration.KLIQID
	}
	if registration.Identity.Status == "" {
		registration.Identity.Status = "active"
	}
	if registration.Identity.IssuedAt.IsZero() {
		registration.Identity.IssuedAt = registration.RegisteredAt
	}
	s.registrations[registration.KLIQID] = registration
	s.identities[registration.KLIQID] = registration.Identity
	s.appendAuditLocked(domain.ManagementAuditEvent{
		EventType:   "kliq_enrolled",
		Actor:       auditActor(ctx),
		TargetType:  "kliq_registration",
		TargetID:    registration.RegistrationID,
		KLIQID:      registration.KLIQID,
		Environment: registration.Environment,
		Stage:       registration.Stage,
		Scope:       registration.Scope,
		Metadata:    auditMetadata(ctx, map[string]any{"kliq_id": registration.KLIQID}),
		CreatedAt:   registration.RegisteredAt,
	})
	s.appendAuditLocked(domain.ManagementAuditEvent{
		EventType:   "identity_issued",
		Actor:       auditActor(ctx),
		TargetType:  "kliq_identity",
		TargetID:    registration.Identity.IdentityID,
		KLIQID:      registration.KLIQID,
		Environment: registration.Environment,
		Stage:       registration.Stage,
		Scope:       registration.Scope,
		Metadata:    auditMetadata(ctx, map[string]any{"kliq_id": registration.KLIQID}),
		CreatedAt:   registration.Identity.IssuedAt,
	})
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

func (s *MemoryStore) Identity(_ context.Context, kliqID string) (domain.KLIQIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, ok := s.identities[kliqID]
	if !ok {
		return domain.KLIQIdentity{}, ErrNotFound
	}
	return identity, nil
}

func (s *MemoryStore) RevokeKLIQ(ctx context.Context, kliqID, reason string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	registration, ok := s.registrations[kliqID]
	if !ok {
		return ErrNotFound
	}
	registration.Status = "revoked"
	registration.RevokedAt = revokedAt.UTC()
	registration.RevokedReason = reason
	s.registrations[kliqID] = registration
	identity := s.identities[kliqID]
	identity.Status = "revoked"
	identity.RevokedAt = revokedAt.UTC()
	identity.RevokedReason = reason
	s.identities[kliqID] = identity
	s.revocations["kliq_registration:"+kliqID] = domain.KLIQRevocation{
		RevocationID: "revocation." + shortHash("kliq_registration:"+kliqID+revokedAt.String()),
		TargetType:   "kliq_registration",
		TargetID:     kliqID,
		Reason:       reason,
		CreatedAt:    revokedAt.UTC(),
		CreatedBy:    auditActor(ctx),
	}
	s.appendAuditLocked(domain.ManagementAuditEvent{
		EventType:  "revocation",
		Actor:      auditActor(ctx),
		TargetType: "kliq_registration",
		TargetID:   kliqID,
		KLIQID:     kliqID,
		Metadata:   map[string]any{"reason": reason},
		CreatedAt:  revokedAt.UTC(),
	})
	return nil
}

func (s *MemoryStore) SaveTrustBundle(_ context.Context, bundle domain.TrustBundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bundle.KeyID == "" {
		return fmt.Errorf("trust bundle requires key_id")
	}
	if existing, ok := s.trustBundles[bundle.KeyID]; ok && existing.Status == "revoked" && bundle.Status == "active" {
		return fmt.Errorf("trust bundle %q is revoked and cannot be reactivated", bundle.KeyID)
	}
	s.trustBundles[bundle.KeyID] = bundle
	return nil
}

func (s *MemoryStore) TrustBundle(_ context.Context, keyID string) (domain.TrustBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bundle, ok := s.trustBundles[keyID]
	if !ok {
		return domain.TrustBundle{}, ErrNotFound
	}
	return bundle, nil
}

func (s *MemoryStore) RevokeTrustBundle(ctx context.Context, keyID, reason string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bundle, ok := s.trustBundles[keyID]
	if !ok {
		return ErrNotFound
	}
	bundle.Status = "revoked"
	s.trustBundles[keyID] = bundle
	s.revocations["trust_key:"+keyID] = domain.KLIQRevocation{
		RevocationID: "revocation." + shortHash("trust_key:"+keyID+revokedAt.String()),
		TargetType:   "trust_key",
		TargetID:     keyID,
		Reason:       reason,
		CreatedAt:    revokedAt.UTC(),
		CreatedBy:    auditActor(ctx),
	}
	s.appendAuditLocked(domain.ManagementAuditEvent{
		EventType:  "revocation",
		Actor:      auditActor(ctx),
		TargetType: "trust_key",
		TargetID:   keyID,
		Metadata:   map[string]any{"reason": reason},
		CreatedAt:  revokedAt.UTC(),
	})
	return nil
}

func (s *MemoryStore) NextAssignmentVersion(_ context.Context, kliqID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.assignments[kliqID]
	if !ok {
		return 1, nil
	}
	return record.Version + 1, nil
}

func (s *MemoryStore) SaveAssignment(ctx context.Context, kliqID string, version int64, envelope signing.SignedEnvelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if kliqID == "" || version <= 0 {
		return fmt.Errorf("assignment requires kliq_id and positive assignment_version")
	}
	existing, ok := s.assignments[kliqID]
	if ok && version < existing.Version {
		return fmt.Errorf("assignment version %d is older than existing version %d", version, existing.Version)
	}
	if ok && version == existing.Version {
		if assignmentDigest(existing.Envelope) == assignmentDigest(envelope) {
			return nil
		}
		return fmt.Errorf("assignment version %d already exists with different digest", version)
	}
	s.assignments[kliqID] = assignmentRecord{Version: version, Envelope: envelope}
	s.appendAuditLocked(domain.ManagementAuditEvent{
		EventType:  "assignment_published",
		Actor:      auditActor(ctx),
		TargetType: "kliq_assignment",
		TargetID:   fmt.Sprintf("%s:%d", kliqID, version),
		KLIQID:     kliqID,
		Metadata:   map[string]any{"digest": assignmentDigest(envelope)},
		CreatedAt:  time.Now().UTC(),
	})
	return nil
}

func (s *MemoryStore) LatestAssignment(ctx context.Context, kliqID string) (signing.SignedEnvelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.assignments[kliqID]
	if !ok {
		return signing.SignedEnvelope{}, ErrNotFound
	}
	if !record.RevokedAt.IsZero() {
		return signing.SignedEnvelope{}, ErrNotFound
	}
	s.appendAuditLocked(domain.ManagementAuditEvent{
		EventType:  "assignment_pulled",
		Actor:      auditActor(ctx),
		TargetType: "kliq_assignment",
		TargetID:   fmt.Sprintf("%s:%d", kliqID, record.Version),
		KLIQID:     kliqID,
		Metadata:   map[string]any{"digest": assignmentDigest(record.Envelope)},
		CreatedAt:  time.Now().UTC(),
	})
	return record.Envelope, nil
}

func (s *MemoryStore) RevokeAssignment(ctx context.Context, kliqID string, version int64, reason string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.assignments[kliqID]
	if !ok || record.Version != version {
		return ErrNotFound
	}
	record.RevokedAt = revokedAt.UTC()
	record.RevokedReason = reason
	s.assignments[kliqID] = record
	s.revocations[fmt.Sprintf("kliq_assignment:%s:%d", kliqID, version)] = domain.KLIQRevocation{
		RevocationID: "revocation." + shortHash(fmt.Sprintf("kliq_assignment:%s:%d:%s", kliqID, version, revokedAt.String())),
		TargetType:   "kliq_assignment",
		TargetID:     fmt.Sprintf("%s:%d", kliqID, version),
		Reason:       reason,
		CreatedAt:    revokedAt.UTC(),
		CreatedBy:    auditActor(ctx),
	}
	s.appendAuditLocked(domain.ManagementAuditEvent{
		EventType:  "revocation",
		Actor:      auditActor(ctx),
		TargetType: "kliq_assignment",
		TargetID:   fmt.Sprintf("%s:%d", kliqID, version),
		KLIQID:     kliqID,
		Metadata:   map[string]any{"reason": reason},
		CreatedAt:  revokedAt.UTC(),
	})
	return nil
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

func (s *MemoryStore) SaveAuditEvent(ctx context.Context, event domain.ManagementAuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.Actor == "" {
		event.Actor = auditActor(ctx)
	}
	s.appendAuditLocked(event)
	return nil
}

func (s *MemoryStore) AuditEvents(_ context.Context, targetType, targetID string) ([]domain.ManagementAuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var events []domain.ManagementAuditEvent
	for _, event := range s.auditEvents {
		if targetType != "" && event.TargetType != targetType {
			continue
		}
		if targetID != "" && event.TargetID != targetID {
			continue
		}
		events = append(events, event)
	}
	return events, nil
}

func StableKLIQID(nodeID, environment, stage, scope string) string {
	sum := sha256.Sum256([]byte(nodeID + "\x00" + environment + "\x00" + stage + "\x00" + scope))
	return "kliq." + hex.EncodeToString(sum[:])[:16]
}

func (s *MemoryStore) appendAuditLocked(event domain.ManagementAuditEvent) {
	if event.EventID == "" {
		event.EventID = "management_audit_event." + shortHash(event.EventType+event.TargetType+event.TargetID+event.CreatedAt.String())
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	s.auditEvents = append(s.auditEvents, event)
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}

func assignmentDigest(envelope signing.SignedEnvelope) string {
	if envelope.PayloadSHA256 != "" {
		return envelope.PayloadSHA256
	}
	sum := sha256.Sum256(envelope.Payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
