// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package management

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/kernloom/kernloom-core/internal/core/domain"
	"github.com/kernloom/kernloom-core/internal/core/signing"
)

type PostgresStore struct {
	db *sql.DB
}

func OpenPostgres(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("postgres management dsn is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	store := &PostgresStore{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *PostgresStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS kliq_enrollment_tokens (
			token_id TEXT PRIMARY KEY,
			token_sha256 TEXT NOT NULL UNIQUE,
			environment TEXT NOT NULL,
			stage TEXT NOT NULL,
			scope TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			used_at TIMESTAMPTZ,
			revoked_at TIMESTAMPTZ,
			revoked_reason TEXT NOT NULL DEFAULT '',
			token_json JSONB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS kliq_registrations (
			kliq_id TEXT PRIMARY KEY,
			registration_id TEXT NOT NULL UNIQUE,
			node_id TEXT NOT NULL,
			environment TEXT NOT NULL,
			stage TEXT NOT NULL,
			scope TEXT NOT NULL,
			status TEXT NOT NULL,
			registered_at TIMESTAMPTZ NOT NULL,
			revoked_at TIMESTAMPTZ,
			revoked_reason TEXT NOT NULL DEFAULT '',
			registration_json JSONB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS kliq_identities (
			identity_id TEXT PRIMARY KEY,
			kliq_id TEXT NOT NULL UNIQUE REFERENCES kliq_registrations(kliq_id),
			node_id TEXT NOT NULL,
			environment TEXT NOT NULL,
			stage TEXT NOT NULL,
			scope TEXT NOT NULL,
			trust_key_id TEXT NOT NULL,
			public_key_pem TEXT NOT NULL,
			csr_pem TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			issued_at TIMESTAMPTZ NOT NULL,
			revoked_at TIMESTAMPTZ,
			revoked_reason TEXT NOT NULL DEFAULT '',
			identity_json JSONB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS trust_bundles (
			key_id TEXT PRIMARY KEY,
			public_key TEXT NOT NULL,
			purpose TEXT NOT NULL,
			status TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			issuer TEXT NOT NULL,
			trust_bundle_json JSONB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS kliq_assignments (
			kliq_id TEXT NOT NULL REFERENCES kliq_registrations(kliq_id),
			assignment_version BIGINT NOT NULL,
			assignment_id TEXT NOT NULL,
			source_commit TEXT NOT NULL,
			trust_bundle_ref TEXT NOT NULL,
			payload_sha256 TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			revoked_at TIMESTAMPTZ,
			revoked_reason TEXT NOT NULL DEFAULT '',
			envelope_json JSONB NOT NULL,
			PRIMARY KEY (kliq_id, assignment_version)
		)`,
		`CREATE TABLE IF NOT EXISTS kliq_assignment_artifacts (
			kliq_id TEXT NOT NULL,
			assignment_version BIGINT NOT NULL,
			artifact_type TEXT NOT NULL,
			artifact_id TEXT NOT NULL,
			artifact_ref TEXT NOT NULL DEFAULT '',
			sha256 TEXT NOT NULL,
			artifact_json JSONB NOT NULL,
			PRIMARY KEY (kliq_id, assignment_version, artifact_type, artifact_id)
		)`,
		`CREATE TABLE IF NOT EXISTS kliq_heartbeats (
			kliq_id TEXT PRIMARY KEY REFERENCES kliq_registrations(kliq_id),
			environment TEXT NOT NULL,
			stage TEXT NOT NULL,
			scope TEXT NOT NULL,
			assignment_version BIGINT NOT NULL,
			status TEXT NOT NULL,
			reported_at TIMESTAMPTZ NOT NULL,
			heartbeat_json JSONB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS kliq_status_reports (
			kliq_id TEXT PRIMARY KEY REFERENCES kliq_registrations(kliq_id),
			environment TEXT NOT NULL,
			stage TEXT NOT NULL,
			scope TEXT NOT NULL,
			assignment_version BIGINT NOT NULL,
			status TEXT NOT NULL,
			reported_at TIMESTAMPTZ NOT NULL,
			status_report_json JSONB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS kliq_revocations (
			revocation_id TEXT PRIMARY KEY,
			target_type TEXT NOT NULL,
			target_id TEXT NOT NULL,
			reason TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			created_by TEXT NOT NULL DEFAULT '',
			revocation_json JSONB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS management_audit_events (
			event_id TEXT PRIMARY KEY,
			event_type TEXT NOT NULL,
			actor TEXT NOT NULL DEFAULT '',
			target_type TEXT NOT NULL,
			target_id TEXT NOT NULL,
			kliq_id TEXT NOT NULL DEFAULT '',
			environment TEXT NOT NULL DEFAULT '',
			stage TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL,
			event_json JSONB NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) CreateEnrollmentToken(ctx context.Context, token domain.KLIQEnrollmentToken, secret string) error {
	if token.TokenID == "" || secret == "" {
		return fmt.Errorf("enrollment token id and secret are required")
	}
	token.TokenSHA256 = TokenSHA256(secret)
	if token.CreatedAt.IsZero() {
		token.CreatedAt = time.Now().UTC()
	}
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO kliq_enrollment_tokens
		(token_id, token_sha256, environment, stage, scope, expires_at, created_at, token_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		token.TokenID, token.TokenSHA256, token.Environment, token.Stage, token.Scope, token.ExpiresAt, token.CreatedAt, data)
	if err != nil {
		return err
	}
	return s.SaveAuditEvent(ctx, auditEvent(ctx, "enrollment_token_created", "kliq_enrollment_token", token.TokenID, "", token.Environment, token.Stage, token.Scope, token.CreatedAt, nil))
}

func (s *PostgresStore) EnrollmentToken(ctx context.Context, tokenID string) (domain.KLIQEnrollmentToken, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT token_json FROM kliq_enrollment_tokens WHERE token_id = $1`, tokenID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.KLIQEnrollmentToken{}, ErrNotFound
	}
	if err != nil {
		return domain.KLIQEnrollmentToken{}, err
	}
	var token domain.KLIQEnrollmentToken
	return token, json.Unmarshal(data, &token)
}

func (s *PostgresStore) UseEnrollmentToken(ctx context.Context, secret, environment, stage, scope string, usedAt time.Time) (domain.KLIQEnrollmentToken, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.KLIQEnrollmentToken{}, err
	}
	defer tx.Rollback()
	var data []byte
	tokenHash := TokenSHA256(secret)
	err = tx.QueryRowContext(ctx, `SELECT token_json FROM kliq_enrollment_tokens WHERE token_sha256 = $1 FOR UPDATE`, tokenHash).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.KLIQEnrollmentToken{}, ErrNotFound
	}
	if err != nil {
		return domain.KLIQEnrollmentToken{}, err
	}
	var token domain.KLIQEnrollmentToken
	if err := json.Unmarshal(data, &token); err != nil {
		return domain.KLIQEnrollmentToken{}, err
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
	data, err = json.Marshal(token)
	if err != nil {
		return domain.KLIQEnrollmentToken{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE kliq_enrollment_tokens SET used_at = $1, token_json = $2 WHERE token_id = $3`, token.UsedAt, data, token.TokenID); err != nil {
		return domain.KLIQEnrollmentToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.KLIQEnrollmentToken{}, err
	}
	return token, s.SaveAuditEvent(ctx, auditEvent(ctx, "enrollment_token_used", "kliq_enrollment_token", token.TokenID, "", token.Environment, token.Stage, token.Scope, token.UsedAt, nil))
}

func (s *PostgresStore) RevokeEnrollmentToken(ctx context.Context, tokenID, reason string, revokedAt time.Time) error {
	token, err := s.EnrollmentToken(ctx, tokenID)
	if err != nil {
		return err
	}
	token.RevokedAt = revokedAt.UTC()
	token.RevokedReason = reason
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE kliq_enrollment_tokens SET revoked_at = $1, revoked_reason = $2, token_json = $3 WHERE token_id = $4`,
		token.RevokedAt, reason, data, tokenID); err != nil {
		return err
	}
	return s.saveRevocation(ctx, "kliq_enrollment_token", tokenID, reason, revokedAt, "")
}

func (s *PostgresStore) Register(ctx context.Context, registration domain.KLIQRegistration) error {
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
	registrationJSON, err := json.Marshal(registration)
	if err != nil {
		return err
	}
	identityJSON, err := json.Marshal(registration.Identity)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO kliq_registrations
		(kliq_id, registration_id, node_id, environment, stage, scope, status, registered_at, registration_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		registration.KLIQID, registration.RegistrationID, registration.NodeID, registration.Environment, registration.Stage,
		registration.Scope, registration.Status, registration.RegisteredAt, registrationJSON); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO kliq_identities
		(identity_id, kliq_id, node_id, environment, stage, scope, trust_key_id, public_key_pem, csr_pem, status, issued_at, identity_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		registration.Identity.IdentityID, registration.KLIQID, registration.NodeID, registration.Environment, registration.Stage,
		registration.Scope, registration.Identity.TrustKeyID, registration.Identity.PublicKeyPEM, registration.Identity.CSRPEM,
		registration.Identity.Status, registration.Identity.IssuedAt, identityJSON); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := s.SaveAuditEvent(ctx, auditEvent(ctx, "kliq_enrolled", "kliq_registration", registration.RegistrationID, registration.KLIQID, registration.Environment, registration.Stage, registration.Scope, registration.RegisteredAt, map[string]any{"kliq_id": registration.KLIQID})); err != nil {
		return err
	}
	return s.SaveAuditEvent(ctx, auditEvent(ctx, "identity_issued", "kliq_identity", registration.Identity.IdentityID, registration.KLIQID, registration.Environment, registration.Stage, registration.Scope, registration.Identity.IssuedAt, map[string]any{"kliq_id": registration.KLIQID}))
}

func (s *PostgresStore) Registration(ctx context.Context, kliqID string) (domain.KLIQRegistration, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT registration_json FROM kliq_registrations WHERE kliq_id = $1`, kliqID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.KLIQRegistration{}, ErrNotFound
	}
	if err != nil {
		return domain.KLIQRegistration{}, err
	}
	var registration domain.KLIQRegistration
	return registration, json.Unmarshal(data, &registration)
}

func (s *PostgresStore) Identity(ctx context.Context, kliqID string) (domain.KLIQIdentity, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT identity_json FROM kliq_identities WHERE kliq_id = $1`, kliqID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.KLIQIdentity{}, ErrNotFound
	}
	if err != nil {
		return domain.KLIQIdentity{}, err
	}
	var identity domain.KLIQIdentity
	return identity, json.Unmarshal(data, &identity)
}

func (s *PostgresStore) RevokeKLIQ(ctx context.Context, kliqID, reason string, revokedAt time.Time) error {
	registration, err := s.Registration(ctx, kliqID)
	if err != nil {
		return err
	}
	registration.Status = "revoked"
	registration.RevokedAt = revokedAt.UTC()
	registration.RevokedReason = reason
	registration.Identity.Status = "revoked"
	registration.Identity.RevokedAt = revokedAt.UTC()
	registration.Identity.RevokedReason = reason
	registrationJSON, err := json.Marshal(registration)
	if err != nil {
		return err
	}
	identityJSON, err := json.Marshal(registration.Identity)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE kliq_registrations SET status = 'revoked', revoked_at = $1, revoked_reason = $2, registration_json = $3 WHERE kliq_id = $4`,
		registration.RevokedAt, reason, registrationJSON, kliqID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE kliq_identities SET status = 'revoked', revoked_at = $1, revoked_reason = $2, identity_json = $3 WHERE kliq_id = $4`,
		registration.Identity.RevokedAt, reason, identityJSON, kliqID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.saveRevocation(ctx, "kliq_registration", kliqID, reason, revokedAt, kliqID)
}

func (s *PostgresStore) SaveTrustBundle(ctx context.Context, bundle domain.TrustBundle) error {
	if bundle.KeyID == "" {
		return fmt.Errorf("trust bundle requires key_id")
	}
	existing, err := s.TrustBundle(ctx, bundle.KeyID)
	if err == nil && existing.Status == "revoked" && bundle.Status == "active" {
		return fmt.Errorf("trust bundle %q is revoked and cannot be reactivated", bundle.KeyID)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO trust_bundles
		(key_id, public_key, purpose, status, expires_at, issuer, trust_bundle_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (key_id) DO UPDATE SET
			public_key = EXCLUDED.public_key,
			purpose = EXCLUDED.purpose,
			status = EXCLUDED.status,
			expires_at = EXCLUDED.expires_at,
			issuer = EXCLUDED.issuer,
			trust_bundle_json = EXCLUDED.trust_bundle_json`,
		bundle.KeyID, bundle.PublicKey, bundle.Purpose, bundle.Status, bundle.ExpiresAt, bundle.Issuer, data)
	return err
}

func (s *PostgresStore) TrustBundle(ctx context.Context, keyID string) (domain.TrustBundle, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT trust_bundle_json FROM trust_bundles WHERE key_id = $1`, keyID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.TrustBundle{}, ErrNotFound
	}
	if err != nil {
		return domain.TrustBundle{}, err
	}
	var bundle domain.TrustBundle
	return bundle, json.Unmarshal(data, &bundle)
}

func (s *PostgresStore) RevokeTrustBundle(ctx context.Context, keyID, reason string, revokedAt time.Time) error {
	bundle, err := s.TrustBundle(ctx, keyID)
	if err != nil {
		return err
	}
	bundle.Status = "revoked"
	if err := s.SaveTrustBundle(ctx, bundle); err != nil {
		return err
	}
	return s.saveRevocation(ctx, "trust_key", keyID, reason, revokedAt, "")
}

func (s *PostgresStore) NextAssignmentVersion(ctx context.Context, kliqID string) (int64, error) {
	var version sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT max(assignment_version) FROM kliq_assignments WHERE kliq_id = $1`, kliqID).Scan(&version); err != nil {
		return 0, err
	}
	if !version.Valid {
		return 1, nil
	}
	return version.Int64 + 1, nil
}

func (s *PostgresStore) SaveAssignment(ctx context.Context, kliqID string, version int64, envelope signing.SignedEnvelope) error {
	if kliqID == "" || version <= 0 {
		return fmt.Errorf("assignment requires kliq_id and positive assignment_version")
	}
	existing, err := s.assignmentEnvelope(ctx, kliqID, version)
	if err == nil {
		if assignmentDigest(existing) == assignmentDigest(envelope) {
			return nil
		}
		return fmt.Errorf("assignment version %d already exists with different digest", version)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	next, err := s.NextAssignmentVersion(ctx, kliqID)
	if err != nil {
		return err
	}
	if version < next {
		return fmt.Errorf("assignment version %d is older than existing version %d", version, next-1)
	}
	var assignment domain.KLIQAssignment
	if err := json.Unmarshal(envelope.Payload, &assignment); err != nil {
		return err
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO kliq_assignments
		(kliq_id, assignment_version, assignment_id, source_commit, trust_bundle_ref, payload_sha256, expires_at, created_at, envelope_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		kliqID, version, assignment.AssignmentID, assignment.SourceCommit, assignment.TrustBundleRef,
		assignmentDigest(envelope), assignment.ExpiresAt, assignment.CreatedAt, envelopeJSON); err != nil {
		return err
	}
	for _, artifact := range assignment.Artifacts {
		artifactJSON, err := json.Marshal(artifact)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO kliq_assignment_artifacts
			(kliq_id, assignment_version, artifact_type, artifact_id, artifact_ref, sha256, artifact_json)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			kliqID, version, artifact.ArtifactType, artifact.ArtifactID, artifact.ArtifactRef, artifact.SHA256, artifactJSON); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.SaveAuditEvent(ctx, auditEvent(ctx, "assignment_published", "kliq_assignment", fmt.Sprintf("%s:%d", kliqID, version), kliqID, assignment.Environment, assignment.Stage, assignment.Scope, time.Now().UTC(), map[string]any{"digest": assignmentDigest(envelope)}))
}

func (s *PostgresStore) LatestAssignment(ctx context.Context, kliqID string) (signing.SignedEnvelope, error) {
	row := s.db.QueryRowContext(ctx, `SELECT envelope_json, revoked_at FROM kliq_assignments
		WHERE kliq_id = $1
		ORDER BY assignment_version DESC LIMIT 1`, kliqID)
	var data []byte
	var revokedAt sql.NullTime
	if err := row.Scan(&data, &revokedAt); errors.Is(err, sql.ErrNoRows) {
		return signing.SignedEnvelope{}, ErrNotFound
	} else if err != nil {
		return signing.SignedEnvelope{}, err
	}
	if revokedAt.Valid {
		return signing.SignedEnvelope{}, ErrNotFound
	}
	var envelope signing.SignedEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return signing.SignedEnvelope{}, err
	}
	return envelope, s.SaveAuditEvent(ctx, auditEvent(ctx, "assignment_pulled", "kliq_assignment", fmt.Sprintf("%s:%s", kliqID, envelope.PayloadSHA256), kliqID, "", "", "", time.Now().UTC(), map[string]any{"digest": assignmentDigest(envelope)}))
}

func (s *PostgresStore) RevokeAssignment(ctx context.Context, kliqID string, version int64, reason string, revokedAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE kliq_assignments SET revoked_at = $1, revoked_reason = $2 WHERE kliq_id = $3 AND assignment_version = $4`,
		revokedAt.UTC(), reason, kliqID, version)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return s.saveRevocation(ctx, "kliq_assignment", fmt.Sprintf("%s:%d", kliqID, version), reason, revokedAt, kliqID)
}

func (s *PostgresStore) SaveHeartbeat(ctx context.Context, heartbeat domain.KLIQHeartbeat) error {
	data, err := json.Marshal(heartbeat)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO kliq_heartbeats
		(kliq_id, environment, stage, scope, assignment_version, status, reported_at, heartbeat_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (kliq_id) DO UPDATE SET
			environment = EXCLUDED.environment,
			stage = EXCLUDED.stage,
			scope = EXCLUDED.scope,
			assignment_version = EXCLUDED.assignment_version,
			status = EXCLUDED.status,
			reported_at = EXCLUDED.reported_at,
			heartbeat_json = EXCLUDED.heartbeat_json`,
		heartbeat.KLIQID, heartbeat.Environment, heartbeat.Stage, heartbeat.Scope, heartbeat.AssignmentVersion, heartbeat.Status, heartbeat.ReportedAt, data)
	return err
}

func (s *PostgresStore) SaveStatusReport(ctx context.Context, report domain.KLIQStatusReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO kliq_status_reports
		(kliq_id, environment, stage, scope, assignment_version, status, reported_at, status_report_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (kliq_id) DO UPDATE SET
			environment = EXCLUDED.environment,
			stage = EXCLUDED.stage,
			scope = EXCLUDED.scope,
			assignment_version = EXCLUDED.assignment_version,
			status = EXCLUDED.status,
			reported_at = EXCLUDED.reported_at,
			status_report_json = EXCLUDED.status_report_json`,
		report.KLIQID, report.Environment, report.Stage, report.Scope, report.AssignmentVersion, report.Status, report.ReportedAt, data)
	return err
}

func (s *PostgresStore) StatusReport(ctx context.Context, kliqID string) (domain.KLIQStatusReport, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT status_report_json FROM kliq_status_reports WHERE kliq_id = $1`, kliqID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.KLIQStatusReport{}, ErrNotFound
	}
	if err != nil {
		return domain.KLIQStatusReport{}, err
	}
	var report domain.KLIQStatusReport
	return report, json.Unmarshal(data, &report)
}

func (s *PostgresStore) SaveAuditEvent(ctx context.Context, event domain.ManagementAuditEvent) error {
	if event.EventID == "" {
		event.EventID = "management_audit_event." + shortHash(event.EventType+event.TargetType+event.TargetID+event.CreatedAt.String())
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	if event.Actor == "" {
		event.Actor = auditActor(ctx)
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO management_audit_events
		(event_id, event_type, actor, target_type, target_id, kliq_id, environment, stage, scope, created_at, event_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		event.EventID, event.EventType, event.Actor, event.TargetType, event.TargetID, event.KLIQID, event.Environment, event.Stage, event.Scope, event.CreatedAt, data)
	return err
}

func (s *PostgresStore) AuditEvents(ctx context.Context, targetType, targetID string) ([]domain.ManagementAuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT event_json FROM management_audit_events
		WHERE ($1 = '' OR target_type = $1) AND ($2 = '' OR target_id = $2)
		ORDER BY created_at`, targetType, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []domain.ManagementAuditEvent
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var event domain.ManagementAuditEvent
		if err := json.Unmarshal(data, &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *PostgresStore) assignmentEnvelope(ctx context.Context, kliqID string, version int64) (signing.SignedEnvelope, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT envelope_json FROM kliq_assignments WHERE kliq_id = $1 AND assignment_version = $2`, kliqID, version).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return signing.SignedEnvelope{}, ErrNotFound
	}
	if err != nil {
		return signing.SignedEnvelope{}, err
	}
	var envelope signing.SignedEnvelope
	return envelope, json.Unmarshal(data, &envelope)
}

func (s *PostgresStore) saveRevocation(ctx context.Context, targetType, targetID, reason string, revokedAt time.Time, kliqID string) error {
	revocation := domain.KLIQRevocation{
		RevocationID: "revocation." + shortHash(targetType+targetID+revokedAt.String()),
		TargetType:   targetType,
		TargetID:     targetID,
		Reason:       reason,
		CreatedAt:    revokedAt.UTC(),
		CreatedBy:    auditActor(ctx),
	}
	data, err := json.Marshal(revocation)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO kliq_revocations
		(revocation_id, target_type, target_id, reason, created_at, created_by, revocation_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (revocation_id) DO NOTHING`,
		revocation.RevocationID, targetType, targetID, reason, revocation.CreatedAt, revocation.CreatedBy, data); err != nil {
		return err
	}
	return s.SaveAuditEvent(ctx, auditEvent(ctx, "revocation", targetType, targetID, kliqID, "", "", "", revokedAt, map[string]any{"reason": reason}))
}

func auditEvent(ctx context.Context, eventType, targetType, targetID, kliqID, environment, stage, scope string, createdAt time.Time, metadata map[string]any) domain.ManagementAuditEvent {
	return domain.ManagementAuditEvent{
		EventType:   eventType,
		Actor:       auditActor(ctx),
		TargetType:  targetType,
		TargetID:    targetID,
		KLIQID:      kliqID,
		Environment: environment,
		Stage:       stage,
		Scope:       scope,
		Metadata:    auditMetadata(ctx, metadata),
		CreatedAt:   createdAt,
	}
}
