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
			created_at TEXT NOT NULL
		)`,
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
	_, err := s.db.ExecContext(ctx, `INSERT INTO bundle_cache (
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
		verified_at = excluded.verified_at`,
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
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_spool (id, runtime_action_id, status, payload, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		record.ID,
		record.RuntimeActionID,
		record.Status,
		record.Payload,
		formatTime(record.CreatedAt),
	)
	return err
}

func (s *SQLiteStore) PendingAudits(ctx context.Context) ([]AuditRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, runtime_action_id, status, payload, created_at
		FROM audit_spool WHERE status = ? ORDER BY created_at`, "pending_upload")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []AuditRecord
	for rows.Next() {
		var record AuditRecord
		var createdAt string
		if err := rows.Scan(&record.ID, &record.RuntimeActionID, &record.Status, &record.Payload, &createdAt); err != nil {
			return nil, err
		}
		parsed, err := parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		record.CreatedAt = parsed
		records = append(records, record)
	}
	return records, rows.Err()
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

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
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
