// The database schema, as numbered migrations that run in order.

package store

import "fmt"

// migrations change the schema one step at a time. The database keeps the
// number of steps it has done in PRAGMA user_version, so Open only runs the
// new ones. Never edit a migration that's been merged, add a new one.
var migrations = []string{
	// 1: scans and what they found.
	`CREATE TABLE runs (
		id              INTEGER PRIMARY KEY,
		name            TEXT    NOT NULL,
		description     TEXT    NOT NULL DEFAULT '',
		kind            TEXT    NOT NULL,
		settings        TEXT    NOT NULL DEFAULT '{}',
		targets         TEXT    NOT NULL, -- JSON list
		status          TEXT    NOT NULL,
		error           TEXT    NOT NULL DEFAULT '',
		started         INTEGER NOT NULL, -- Unix nanoseconds, 0 when not set
		finished        INTEGER NOT NULL DEFAULT 0,
		has_report      INTEGER NOT NULL DEFAULT 0,
		report_started  INTEGER NOT NULL DEFAULT 0,
		report_finished INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE hosts (
		run_id    INTEGER NOT NULL REFERENCES runs ON DELETE CASCADE,
		address   TEXT    NOT NULL,
		hostnames TEXT    NOT NULL -- JSON list
	);
	CREATE INDEX hosts_run ON hosts (run_id);
	CREATE TABLE services (
		run_id   INTEGER NOT NULL REFERENCES runs ON DELETE CASCADE,
		address  TEXT    NOT NULL,
		port     INTEGER NOT NULL,
		protocol TEXT    NOT NULL,
		name     TEXT    NOT NULL,
		product  TEXT    NOT NULL,
		version  TEXT    NOT NULL,
		tunnel   TEXT    NOT NULL,
		guessed  INTEGER NOT NULL
	);
	CREATE INDEX services_run ON services (run_id);
	CREATE TABLE findings (
		run_id     INTEGER NOT NULL REFERENCES runs ON DELETE CASCADE,
		finding_id TEXT    NOT NULL, -- stable across runs, see model.FindingID
		check_id   TEXT    NOT NULL,
		title      TEXT    NOT NULL,
		severity   INTEGER NOT NULL, -- model.Severity, 0 info to 4 critical
		confidence TEXT    NOT NULL,
		host       TEXT    NOT NULL,
		port       INTEGER NOT NULL,
		protocol   TEXT    NOT NULL,
		evidence   TEXT    NOT NULL,
		fix        TEXT    NOT NULL
	);
	CREATE INDEX findings_run ON findings (run_id);
	CREATE INDEX findings_finding ON findings (finding_id);
	CREATE TABLE check_errors (
		run_id   INTEGER NOT NULL REFERENCES runs ON DELETE CASCADE,
		check_id TEXT    NOT NULL,
		host     TEXT    NOT NULL,
		port     INTEGER NOT NULL,
		error    TEXT    NOT NULL
	);
	CREATE INDEX check_errors_run ON check_errors (run_id);`,
}

// migrate runs the migrations this database hasn't had yet, each in its own
// transaction, so a failed one leaves the database as it was.
func (s *Store) migrate() error {
	var done int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&done); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if done > len(migrations) {
		return fmt.Errorf("the database is from a newer Nuqs (schema %d, this one knows %d), update Nuqs", done, len(migrations))
	}
	for i := done; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		_, err = tx.Exec(migrations[i])
		if err == nil {
			// PRAGMA can't take a ? parameter, i is our own number.
			_, err = tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1))
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("schema step %d: %w", i+1, err)
		}
	}
	return nil
}
