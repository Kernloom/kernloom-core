// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actionstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kernloom/kernloom-core/internal/core/domain"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func OpenSQLite(path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	store := &SQLiteStore{db: db}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS bundle_cache (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			bundle_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			source_commit TEXT NOT NULL,
			correlation_id TEXT NOT NULL DEFAULT '',
			key_id TEXT NOT NULL,
			payload_sha256 TEXT NOT NULL,
			bundle_source TEXT NOT NULL,
			envelope_json BLOB NOT NULL,
			expires_at TEXT NOT NULL,
			verified_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS runtime_action_leases (
			runtime_action_id TEXT PRIMARY KEY,
			plan_id TEXT NOT NULL,
			decision_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			bundle_id TEXT NOT NULL,
			source_commit TEXT NOT NULL,
			correlation_id TEXT NOT NULL DEFAULT '',
			action_type TEXT NOT NULL,
			target_scope TEXT NOT NULL,
			target_key TEXT NOT NULL,
			ttl TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			reason TEXT NOT NULL,
			audit_id TEXT NOT NULL,
			capability_grant_id TEXT NOT NULL,
			adapter_id TEXT NOT NULL,
			capability_id TEXT NOT NULL,
			mode TEXT NOT NULL,
			required INTEGER NOT NULL,
			idempotency_key TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL,
			last_reconciled_at TEXT NOT NULL,
			status TEXT NOT NULL
		)`,
		`ALTER TABLE runtime_action_leases ADD COLUMN plan_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE runtime_action_leases ADD COLUMN capability_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE runtime_action_leases ADD COLUMN correlation_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE runtime_action_leases ADD COLUMN mode TEXT NOT NULL DEFAULT 'required'`,
		`ALTER TABLE runtime_action_leases ADD COLUMN required INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE bundle_cache ADD COLUMN correlation_id TEXT NOT NULL DEFAULT ''`,
		`CREATE TABLE IF NOT EXISTS kliq_management_state (
			kliq_id TEXT PRIMARY KEY,
			active_assignment_id TEXT NOT NULL,
			active_assignment_version INTEGER NOT NULL,
			active_assignment_source_commit TEXT NOT NULL,
			active_assignment_digest TEXT NOT NULL,
			active_assignment_expires_at TEXT NOT NULL,
			active_assignment_activated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS kliq_assignment_artifacts (
			kliq_id TEXT NOT NULL,
			assignment_id TEXT NOT NULL,
			assignment_version INTEGER NOT NULL,
			artifact_type TEXT NOT NULL,
			artifact_id TEXT NOT NULL,
			artifact_ref TEXT NOT NULL DEFAULT '',
			sha256 TEXT NOT NULL,
			envelope_json BLOB NOT NULL,
			activated_at TEXT NOT NULL,
			PRIMARY KEY (kliq_id, assignment_id, artifact_type, artifact_id)
		)`,
		`CREATE TABLE IF NOT EXISTS kliq_credentials (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			kliq_id TEXT NOT NULL,
			node_id TEXT NOT NULL,
			environment TEXT NOT NULL,
			stage TEXT NOT NULL,
			scope TEXT NOT NULL,
			trust_key_id TEXT NOT NULL,
			assignment_url TEXT NOT NULL,
			public_key_pem TEXT NOT NULL,
			private_key_pem TEXT NOT NULL,
			service_token TEXT NOT NULL,
			service_token_expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`DROP INDEX IF EXISTS runtime_action_leases_dedup`,
		`CREATE UNIQUE INDEX IF NOT EXISTS runtime_action_leases_dedup
			ON runtime_action_leases(adapter_id, capability_id, action_type, target_scope, target_key)
			WHERE status IN ('planned', 'authorized', 'executing', 'active', 'expiring', 'unknown', 'compensating')`,
		`CREATE TABLE IF NOT EXISTS runtime_action_journal (
			id TEXT PRIMARY KEY,
			runtime_action_id TEXT NOT NULL,
			event TEXT NOT NULL,
			status TEXT NOT NULL,
			message TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS audit_spool (
			id TEXT PRIMARY KEY,
			runtime_action_id TEXT NOT NULL,
			status TEXT NOT NULL,
			payload TEXT NOT NULL,
			created_at TEXT NOT NULL,
			retry_count INTEGER NOT NULL DEFAULT 0,
			last_attempt_at TEXT NOT NULL DEFAULT '',
			uploaded_at TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT ''
		)`,
		`ALTER TABLE audit_spool ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE audit_spool ADD COLUMN last_attempt_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_spool ADD COLUMN uploaded_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_spool ADD COLUMN last_error TEXT NOT NULL DEFAULT ''`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			if isDuplicateColumnError(err) {
				continue
			}
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) SaveBundle(ctx context.Context, record BundleRecord) error {
	_, err := s.db.ExecContext(ctx, saveBundleSQL(),
		record.BundleID,
		record.PolicyID,
		record.SourceCommit,
		record.CorrelationID,
		record.KeyID,
		record.PayloadSHA256,
		record.BundleSource,
		record.EnvelopeJSON,
		formatTime(record.ExpiresAt),
		formatTime(record.VerifiedAt),
	)
	return err
}

func (s *SQLiteStore) SaveManagedBundleActivation(ctx context.Context, record BundleRecord, state KLIQManagementState, artifacts []AssignmentArtifactRecord) error {
	if err := validateKLIQManagementState(state); err != nil {
		return err
	}
	for _, artifact := range artifacts {
		if err := validateAssignmentArtifactRecord(artifact); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, saveBundleSQL(),
		record.BundleID,
		record.PolicyID,
		record.SourceCommit,
		record.CorrelationID,
		record.KeyID,
		record.PayloadSHA256,
		record.BundleSource,
		record.EnvelopeJSON,
		formatTime(record.ExpiresAt),
		formatTime(record.VerifiedAt),
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, saveKLIQManagementStateSQL(),
		state.KLIQID,
		state.ActiveAssignmentID,
		state.ActiveAssignmentVersion,
		state.ActiveAssignmentSourceCommit,
		state.ActiveAssignmentDigest,
		formatTime(state.ActiveAssignmentExpiresAt),
		formatTime(state.ActiveAssignmentActivatedAt),
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM kliq_assignment_artifacts WHERE kliq_id = ?`, state.KLIQID); err != nil {
		return err
	}
	for _, artifact := range artifacts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO kliq_assignment_artifacts (
			kliq_id, assignment_id, assignment_version, artifact_type, artifact_id, artifact_ref, sha256, envelope_json, activated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			artifact.KLIQID,
			artifact.AssignmentID,
			artifact.AssignmentVersion,
			artifact.ArtifactType,
			artifact.ArtifactID,
			artifact.ArtifactRef,
			artifact.SHA256,
			artifact.EnvelopeJSON,
			formatTime(artifact.ActivatedAt),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func validateAssignmentArtifactRecord(record AssignmentArtifactRecord) error {
	required := map[string]string{
		"kliq_id":       record.KLIQID,
		"assignment_id": record.AssignmentID,
		"artifact_type": record.ArtifactType,
		"artifact_id":   record.ArtifactID,
		"sha256":        record.SHA256,
	}
	for field, value := range required {
		if value == "" {
			return fmt.Errorf("assignment artifact record requires %s", field)
		}
	}
	if record.AssignmentVersion <= 0 {
		return fmt.Errorf("assignment artifact record requires positive assignment_version")
	}
	if len(record.EnvelopeJSON) == 0 {
		return fmt.Errorf("assignment artifact record requires envelope_json")
	}
	if record.ActivatedAt.IsZero() {
		return fmt.Errorf("assignment artifact record requires activated_at")
	}
	return nil
}

func saveBundleSQL() string {
	return `INSERT INTO bundle_cache (
		id, bundle_id, policy_id, source_commit, correlation_id, key_id, payload_sha256, bundle_source, envelope_json, expires_at, verified_at
	) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		bundle_id = excluded.bundle_id,
		policy_id = excluded.policy_id,
		source_commit = excluded.source_commit,
		correlation_id = excluded.correlation_id,
		key_id = excluded.key_id,
		payload_sha256 = excluded.payload_sha256,
		bundle_source = excluded.bundle_source,
		envelope_json = excluded.envelope_json,
		expires_at = excluded.expires_at,
		verified_at = excluded.verified_at`
}

func (s *SQLiteStore) LastBundle(ctx context.Context) (BundleRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT bundle_id, policy_id, source_commit, correlation_id, key_id, payload_sha256, bundle_source, envelope_json, expires_at, verified_at FROM bundle_cache WHERE id = 1`)
	var record BundleRecord
	var expiresAt, verifiedAt string
	if err := row.Scan(&record.BundleID, &record.PolicyID, &record.SourceCommit, &record.CorrelationID, &record.KeyID, &record.PayloadSHA256, &record.BundleSource, &record.EnvelopeJSON, &expiresAt, &verifiedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return BundleRecord{}, ErrNotFound
		}
		return BundleRecord{}, err
	}
	var err error
	record.ExpiresAt, err = parseTime(expiresAt)
	if err != nil {
		return BundleRecord{}, err
	}
	record.VerifiedAt, err = parseTime(verifiedAt)
	if err != nil {
		return BundleRecord{}, err
	}
	return record, nil
}

func (s *SQLiteStore) SaveKLIQCredential(ctx context.Context, credential KLIQCredential) error {
	required := map[string]string{
		"kliq_id":         credential.KLIQID,
		"node_id":         credential.NodeID,
		"environment":     credential.Environment,
		"stage":           credential.Stage,
		"scope":           credential.Scope,
		"trust_key_id":    credential.TrustKeyID,
		"assignment_url":  credential.AssignmentURL,
		"public_key_pem":  credential.PublicKeyPEM,
		"private_key_pem": credential.PrivateKeyPEM,
		"service_token":   credential.ServiceToken,
	}
	for field, value := range required {
		if value == "" {
			return fmt.Errorf("kliq credential requires %s", field)
		}
	}
	if credential.ServiceTokenExpiresAt.IsZero() {
		return fmt.Errorf("kliq credential requires service_token_expires_at")
	}
	if credential.CreatedAt.IsZero() {
		credential.CreatedAt = time.Now().UTC()
	}
	if credential.UpdatedAt.IsZero() {
		credential.UpdatedAt = credential.CreatedAt
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO kliq_credentials (
		id, kliq_id, node_id, environment, stage, scope, trust_key_id, assignment_url, public_key_pem,
		private_key_pem, service_token, service_token_expires_at, created_at, updated_at
	) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		kliq_id = excluded.kliq_id,
		node_id = excluded.node_id,
		environment = excluded.environment,
		stage = excluded.stage,
		scope = excluded.scope,
		trust_key_id = excluded.trust_key_id,
		assignment_url = excluded.assignment_url,
		public_key_pem = excluded.public_key_pem,
		private_key_pem = excluded.private_key_pem,
		service_token = excluded.service_token,
		service_token_expires_at = excluded.service_token_expires_at,
		updated_at = excluded.updated_at`,
		credential.KLIQID,
		credential.NodeID,
		credential.Environment,
		credential.Stage,
		credential.Scope,
		credential.TrustKeyID,
		credential.AssignmentURL,
		credential.PublicKeyPEM,
		credential.PrivateKeyPEM,
		credential.ServiceToken,
		formatTime(credential.ServiceTokenExpiresAt),
		formatTime(credential.CreatedAt),
		formatTime(credential.UpdatedAt),
	)
	return err
}

func (s *SQLiteStore) KLIQCredential(ctx context.Context) (KLIQCredential, error) {
	row := s.db.QueryRowContext(ctx, `SELECT
		kliq_id, node_id, environment, stage, scope, trust_key_id, assignment_url, public_key_pem,
		private_key_pem, service_token, service_token_expires_at, created_at, updated_at
		FROM kliq_credentials WHERE id = 1`)
	var credential KLIQCredential
	var tokenExpiresAt, createdAt, updatedAt string
	if err := row.Scan(
		&credential.KLIQID,
		&credential.NodeID,
		&credential.Environment,
		&credential.Stage,
		&credential.Scope,
		&credential.TrustKeyID,
		&credential.AssignmentURL,
		&credential.PublicKeyPEM,
		&credential.PrivateKeyPEM,
		&credential.ServiceToken,
		&tokenExpiresAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return KLIQCredential{}, ErrNotFound
		}
		return KLIQCredential{}, err
	}
	var err error
	credential.ServiceTokenExpiresAt, err = parseTime(tokenExpiresAt)
	if err != nil {
		return KLIQCredential{}, err
	}
	credential.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return KLIQCredential{}, err
	}
	credential.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return KLIQCredential{}, err
	}
	return credential, nil
}

func (s *SQLiteStore) SaveKLIQManagementState(ctx context.Context, state KLIQManagementState) error {
	if err := validateKLIQManagementState(state); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, saveKLIQManagementStateSQL(),
		state.KLIQID,
		state.ActiveAssignmentID,
		state.ActiveAssignmentVersion,
		state.ActiveAssignmentSourceCommit,
		state.ActiveAssignmentDigest,
		formatTime(state.ActiveAssignmentExpiresAt),
		formatTime(state.ActiveAssignmentActivatedAt),
	)
	return err
}

func validateKLIQManagementState(state KLIQManagementState) error {
	if state.KLIQID == "" {
		return fmt.Errorf("kliq management state requires kliq_id")
	}
	if state.ActiveAssignmentID == "" {
		return fmt.Errorf("kliq management state requires active_assignment_id")
	}
	if state.ActiveAssignmentVersion <= 0 {
		return fmt.Errorf("kliq management state requires positive active_assignment_version")
	}
	if state.ActiveAssignmentSourceCommit == "" {
		return fmt.Errorf("kliq management state requires active_assignment_source_commit")
	}
	if state.ActiveAssignmentDigest == "" {
		return fmt.Errorf("kliq management state requires active_assignment_digest")
	}
	if state.ActiveAssignmentExpiresAt.IsZero() {
		return fmt.Errorf("kliq management state requires active_assignment_expires_at")
	}
	if state.ActiveAssignmentActivatedAt.IsZero() {
		return fmt.Errorf("kliq management state requires active_assignment_activated_at")
	}
	return nil
}

func saveKLIQManagementStateSQL() string {
	return `INSERT INTO kliq_management_state (
		kliq_id, active_assignment_id, active_assignment_version, active_assignment_source_commit,
		active_assignment_digest, active_assignment_expires_at, active_assignment_activated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(kliq_id) DO UPDATE SET
		active_assignment_id = excluded.active_assignment_id,
		active_assignment_version = excluded.active_assignment_version,
		active_assignment_source_commit = excluded.active_assignment_source_commit,
		active_assignment_digest = excluded.active_assignment_digest,
		active_assignment_expires_at = excluded.active_assignment_expires_at,
		active_assignment_activated_at = excluded.active_assignment_activated_at`
}

func (s *SQLiteStore) KLIQManagementState(ctx context.Context, kliqID string) (KLIQManagementState, error) {
	row := s.db.QueryRowContext(ctx, `SELECT
		kliq_id, active_assignment_id, active_assignment_version, active_assignment_source_commit,
		active_assignment_digest, active_assignment_expires_at, active_assignment_activated_at
		FROM kliq_management_state WHERE kliq_id = ?`, kliqID)
	var state KLIQManagementState
	var expiresAt, activatedAt string
	if err := row.Scan(
		&state.KLIQID,
		&state.ActiveAssignmentID,
		&state.ActiveAssignmentVersion,
		&state.ActiveAssignmentSourceCommit,
		&state.ActiveAssignmentDigest,
		&expiresAt,
		&activatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return KLIQManagementState{}, ErrNotFound
		}
		return KLIQManagementState{}, err
	}
	var err error
	state.ActiveAssignmentExpiresAt, err = parseTime(expiresAt)
	if err != nil {
		return KLIQManagementState{}, err
	}
	state.ActiveAssignmentActivatedAt, err = parseTime(activatedAt)
	if err != nil {
		return KLIQManagementState{}, err
	}
	return state, nil
}

func (s *SQLiteStore) AssignmentArtifacts(ctx context.Context, kliqID string) ([]AssignmentArtifactRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
		kliq_id, assignment_id, assignment_version, artifact_type, artifact_id, artifact_ref, sha256, envelope_json, activated_at
		FROM kliq_assignment_artifacts WHERE kliq_id = ? ORDER BY artifact_type, artifact_id`, kliqID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []AssignmentArtifactRecord
	for rows.Next() {
		var record AssignmentArtifactRecord
		var activatedAt string
		if err := rows.Scan(
			&record.KLIQID,
			&record.AssignmentID,
			&record.AssignmentVersion,
			&record.ArtifactType,
			&record.ArtifactID,
			&record.ArtifactRef,
			&record.SHA256,
			&record.EnvelopeJSON,
			&activatedAt,
		); err != nil {
			return nil, err
		}
		record.ActivatedAt, err = parseTime(activatedAt)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *SQLiteStore) UpsertLease(ctx context.Context, lease RuntimeActionLease) error {
	if err := lease.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO runtime_action_leases (
		runtime_action_id, plan_id, decision_id, policy_id, bundle_id, source_commit, correlation_id, action_type, target_scope, target_key,
		ttl, expires_at, reason, audit_id, capability_grant_id, adapter_id, capability_id, mode, required,
		idempotency_key, created_at, last_reconciled_at, status
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(runtime_action_id) DO UPDATE SET
		last_reconciled_at = excluded.last_reconciled_at,
		status = excluded.status`,
		lease.RuntimeActionID,
		lease.PlanID,
		lease.DecisionID,
		lease.PolicyID,
		lease.BundleID,
		lease.SourceCommit,
		lease.CorrelationID,
		lease.ActionType,
		lease.TargetScope,
		lease.TargetKey,
		lease.TTL,
		formatTime(lease.ExpiresAt),
		lease.Reason,
		lease.AuditID,
		lease.CapabilityGrantID,
		lease.AdapterID,
		lease.CapabilityID,
		lease.Mode,
		boolInt(lease.Required),
		lease.IdempotencyKey,
		formatTime(lease.CreatedAt),
		formatTime(lease.LastReconciledAt),
		string(lease.Status),
	)
	return err
}

func (s *SQLiteStore) LeaseByDedupKey(ctx context.Context, adapterID, capabilityID, actionType, targetScope, targetKey string) (RuntimeActionLease, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+leaseColumns()+` FROM runtime_action_leases
		WHERE adapter_id = ? AND capability_id = ? AND action_type = ? AND target_scope = ? AND target_key = ?
		AND status IN ('planned', 'authorized', 'executing', 'active', 'expiring', 'unknown', 'compensating')
		LIMIT 1`, adapterID, capabilityID, actionType, targetScope, targetKey)
	return scanLease(row)
}

func (s *SQLiteStore) LeaseByID(ctx context.Context, runtimeActionID string) (RuntimeActionLease, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+leaseColumns()+` FROM runtime_action_leases WHERE runtime_action_id = ?`, runtimeActionID)
	return scanLease(row)
}

func (s *SQLiteStore) ActiveLeases(ctx context.Context) ([]RuntimeActionLease, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+leaseColumns()+` FROM runtime_action_leases
		WHERE status IN ('planned', 'authorized', 'executing', 'active', 'expiring', 'unknown', 'compensating')
		ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanLeases(rows)
}

func (s *SQLiteStore) AllLeases(ctx context.Context) ([]RuntimeActionLease, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+leaseColumns()+` FROM runtime_action_leases ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanLeases(rows)
}

func (s *SQLiteStore) ExpireLease(ctx context.Context, runtimeActionID string, reconciledAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runtime_action_leases
		SET status = ?, last_reconciled_at = ?
		WHERE runtime_action_id = ?`, string(domain.RuntimeActionExpired), formatTime(reconciledAt), runtimeActionID)
	return err
}

func (s *SQLiteStore) AppendJournal(ctx context.Context, entry JournalEntry) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO runtime_action_journal (id, runtime_action_id, event, status, message, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		entry.ID,
		entry.RuntimeActionID,
		entry.Event,
		string(entry.Status),
		entry.Message,
		formatTime(entry.CreatedAt),
	)
	return err
}

func (s *SQLiteStore) JournalEntries(ctx context.Context, runtimeActionID string) ([]JournalEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, runtime_action_id, event, status, message, created_at
		FROM runtime_action_journal WHERE runtime_action_id = ? ORDER BY created_at`, runtimeActionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []JournalEntry
	for rows.Next() {
		var entry JournalEntry
		var status, createdAt string
		if err := rows.Scan(&entry.ID, &entry.RuntimeActionID, &entry.Event, &status, &entry.Message, &createdAt); err != nil {
			return nil, err
		}
		parsed, err := parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		entry.Status = domain.RuntimeActionStatus(status)
		entry.CreatedAt = parsed
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *SQLiteStore) AppendAudit(ctx context.Context, record AuditRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_spool (id, runtime_action_id, status, payload, created_at, retry_count, last_attempt_at, uploaded_at, last_error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.RuntimeActionID,
		record.Status,
		record.Payload,
		formatTime(record.CreatedAt),
		record.RetryCount,
		formatOptionalTime(record.LastAttemptAt),
		formatOptionalTime(record.UploadedAt),
		record.LastError,
	)
	return err
}

func (s *SQLiteStore) PendingAudits(ctx context.Context) ([]AuditRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, runtime_action_id, status, payload, created_at, retry_count, last_attempt_at, uploaded_at, last_error
		FROM audit_spool WHERE status = ? ORDER BY created_at`, "pending_upload")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []AuditRecord
	for rows.Next() {
		var record AuditRecord
		var createdAt, lastAttemptAt, uploadedAt string
		if err := rows.Scan(&record.ID, &record.RuntimeActionID, &record.Status, &record.Payload, &createdAt, &record.RetryCount, &lastAttemptAt, &uploadedAt, &record.LastError); err != nil {
			return nil, err
		}
		parsed, err := parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		record.CreatedAt = parsed
		record.LastAttemptAt, err = parseOptionalTime(lastAttemptAt)
		if err != nil {
			return nil, err
		}
		record.UploadedAt, err = parseOptionalTime(uploadedAt)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *SQLiteStore) MarkAuditUploaded(ctx context.Context, id string, uploadedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE audit_spool
		SET status = ?, uploaded_at = ?, last_attempt_at = ?, last_error = ''
		WHERE id = ?`, "uploaded", formatTime(uploadedAt), formatTime(uploadedAt), id)
	return err
}

func (s *SQLiteStore) MarkAuditFailed(ctx context.Context, id string, attemptedAt time.Time, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE audit_spool
		SET status = ?, retry_count = retry_count + 1, last_attempt_at = ?, last_error = ?
		WHERE id = ?`, "pending_upload", formatTime(attemptedAt), message, id)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func leaseColumns() string {
	return `runtime_action_id, plan_id, decision_id, policy_id, bundle_id, source_commit, correlation_id, action_type, target_scope, target_key,
		ttl, expires_at, reason, audit_id, capability_grant_id, adapter_id, capability_id, mode, required, idempotency_key, created_at,
		last_reconciled_at, status`
}

func scanLease(row rowScanner) (RuntimeActionLease, error) {
	var lease RuntimeActionLease
	var expiresAt, createdAt, lastReconciledAt, status string
	var required int
	if err := row.Scan(
		&lease.RuntimeActionID,
		&lease.PlanID,
		&lease.DecisionID,
		&lease.PolicyID,
		&lease.BundleID,
		&lease.SourceCommit,
		&lease.CorrelationID,
		&lease.ActionType,
		&lease.TargetScope,
		&lease.TargetKey,
		&lease.TTL,
		&expiresAt,
		&lease.Reason,
		&lease.AuditID,
		&lease.CapabilityGrantID,
		&lease.AdapterID,
		&lease.CapabilityID,
		&lease.Mode,
		&required,
		&lease.IdempotencyKey,
		&createdAt,
		&lastReconciledAt,
		&status,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RuntimeActionLease{}, ErrNotFound
		}
		return RuntimeActionLease{}, err
	}
	var err error
	lease.ExpiresAt, err = parseTime(expiresAt)
	if err != nil {
		return RuntimeActionLease{}, err
	}
	lease.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return RuntimeActionLease{}, err
	}
	lease.LastReconciledAt, err = parseTime(lastReconciledAt)
	if err != nil {
		return RuntimeActionLease{}, err
	}
	lease.Status = domain.RuntimeActionStatus(status)
	lease.Required = required != 0
	return lease, nil
}

func scanLeases(rows *sql.Rows) ([]RuntimeActionLease, error) {
	var leases []RuntimeActionLease
	for rows.Next() {
		lease, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		leases = append(leases, lease)
	}
	return leases, rows.Err()
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return formatTime(value)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func parseOptionalTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return parseTime(value)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func isDuplicateColumnError(err error) bool {
	return strings.Contains(err.Error(), "duplicate column name")
}
