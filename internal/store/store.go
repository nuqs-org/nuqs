// Package store saves scans, accounts, sessions and recovery codes in a
// SQLite database, so they're still there after Nuqs stops. It keeps every run
// with its hosts, services, findings and check errors, and gives them back
// exactly as they were saved.
//
// One file holds everything, nuqs.db in the data folder. The schema grows
// through numbered migrations in migrations.go, and the database remembers
// which ones it already ran.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/model"
	"modernc.org/sqlite" // the SQLite driver, pure Go so Nuqs still builds without a C compiler
)

// ErrNotFound is returned for a run ID that isn't saved.
var ErrNotFound = errors.New("no saved scan with that ID")

// Run statuses, the same words the web UI uses.
const (
	Running   = "running"
	Completed = "completed"
	Stopped   = "stopped"
	Failed    = "failed"
)

// Run is one scan: what was asked for, how it went and what it found.
type Run struct {
	ID          int64
	Name        string
	Description string
	Kind        string // quick, full, custom, or cli for "nuqs scan"
	StartedBy   string // authenticated username that launched the scan, if any
	Settings    string // the scan settings as JSON, the store only reads the ports (see SameScope)
	Targets     []string
	Status      string
	Error       string
	Started     time.Time
	Finished    time.Time
	Report      *engine.Report // nil until the run is finished, and for failed runs
}

// Summary is a run without its report, plus counts, for history lists.
type Summary struct {
	ID        int64
	Name      string
	Kind      string
	StartedBy string
	Targets   []string
	Status    string
	Started   time.Time
	Finished  time.Time
	Hosts     int
	Findings  [5]int // how many findings at each severity, indexed by model.Severity
}

// Store is an open database. It's safe to use from many goroutines.
type Store struct {
	db *sql.DB
}

// DefaultDir is where Nuqs keeps its data: NUQS_DATA_DIR if set, otherwise
// a "nuqs" folder in the user's config folder (~/Library/Application Support
// on macOS, ~/.config on Linux).
func DefaultDir() string {
	if dir := os.Getenv("NUQS_DATA_DIR"); dir != "" {
		return dir
	}
	if base, err := os.UserConfigDir(); err == nil {
		return filepath.Join(base, "nuqs")
	}
	return ".nuqs"
}

// Open opens nuqs.db in dir, creating the folder and the database when
// they don't exist yet, and brings the schema up to date.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("make the data folder: %w", err)
	}
	path := filepath.Join(dir, "nuqs.db")
	// Make the file ourselves so it's private from the start. SQLite gives
	// its -wal and -shm files the same permissions as the database.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	_ = f.Close()
	_ = os.Chmod(path, 0o600) // in case it was made before with looser permissions
	// WAL lets the CLI and the server use the file at the same time, and
	// busy_timeout makes one wait a bit for the other instead of failing.
	// _txlock=immediate makes every transaction take the write lock when it
	// starts, so two of them never read the same thing and then both write.
	// The path is escaped because "?", "#" and "%" mean something in a
	// SQLite file: URI, and a folder name can contain any of them.
	uri := "file:" + uriEscaper.Replace(path) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate"
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	// One connection: SQLite writes one at a time anyway, and this way the
	// pragmas above always apply and writes never trip over each other.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrateWhenFree(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return s, nil
}

var uriEscaper = strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23")

// migrateWhenFree runs the migrations, waiting if another Nuqs is busy with
// the same new database. While one process turns on WAL mode, SQLite tells
// the others "busy" right away instead of waiting, so we wait for it.
func (s *Store) migrateWhenFree() error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := s.migrate()
		var e *sqlite.Error
		if err == nil || !errors.As(err, &e) || e.Code()&0xff != sqliteBusy || time.Now().After(deadline) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

const sqliteBusy = 5 // SQLITE_BUSY, the low byte of the error code

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// CloseUnfinished marks runs still saved as running as stopped. "nuqs serve"
// calls it when it starts: those runs belong to a server that quit mid-scan.
// ("nuqs scan" only saves when it's done, so it never leaves one behind.)
func (s *Store) CloseUnfinished() error {
	_, err := s.db.Exec(`UPDATE runs SET status = ?, error = ?, finished = started WHERE status = ?`,
		Stopped, "Nuqs stopped before this scan finished.", Running)
	if err != nil {
		return fmt.Errorf("close unfinished scans: %w", err)
	}
	return nil
}

// Save saves a run that's already done, report and all, and sets its ID.
// It's one transaction: if any part fails, nothing is saved.
func (s *Store) Save(r *Run) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("save scan: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // does nothing after Commit
	if err := insertRun(tx, r); err != nil {
		r.ID = 0
		return err
	}
	if err := finishRun(tx, *r); err != nil {
		r.ID = 0
		return err
	}
	if err := tx.Commit(); err != nil {
		r.ID = 0
		return fmt.Errorf("save scan: %w", err)
	}
	return nil
}

// Create saves a run that's starting and sets its ID. Call Finish when it's done.
func (s *Store) Create(r *Run) error {
	return insertRun(s.db, r)
}

// Finish saves how a run ended and everything it found, all at once.
func (s *Store) Finish(r Run) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("save scan %d: %w", r.ID, err)
	}
	defer func() { _ = tx.Rollback() }() // does nothing after Commit
	if err := finishRun(tx, r); err != nil {
		return err
	}
	return tx.Commit()
}

// execer is what both *sql.DB and *sql.Tx can do.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func insertRun(db execer, r *Run) error {
	targets, err := json.Marshal(r.Targets)
	if err != nil {
		return err
	}
	res, err := db.Exec(`INSERT INTO runs (name, description, kind, started_by, settings, targets, status, error, started)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Name, r.Description, r.Kind, r.StartedBy, orEmpty(r.Settings, "{}"), string(targets), orEmpty(r.Status, Running), r.Error, unix(r.Started))
	if err != nil {
		return fmt.Errorf("save scan: %w", err)
	}
	r.ID, err = res.LastInsertId()
	return err
}

func finishRun(tx *sql.Tx, r Run) error {
	var repStarted, repFinished int64
	if rep := r.Report; rep != nil {
		repStarted, repFinished = unix(rep.Started), unix(rep.Finished)
	}
	res, err := tx.Exec(`UPDATE runs SET status = ?, error = ?, finished = ?, has_report = ?, report_started = ?, report_finished = ? WHERE id = ?`,
		r.Status, r.Error, unix(r.Finished), r.Report != nil, repStarted, repFinished, r.ID)
	if err != nil {
		return fmt.Errorf("save scan %d: %w", r.ID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if r.Report != nil {
		if err := saveReport(tx, r.ID, r.Report); err != nil {
			return fmt.Errorf("save scan %d: %w", r.ID, err)
		}
	}
	return nil
}

func saveReport(tx *sql.Tx, id int64, rep *engine.Report) error {
	for _, h := range rep.Hosts {
		names, err := json.Marshal(h.Hostnames)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO hosts (run_id, address, hostnames) VALUES (?, ?, ?)`, id, h.Address, string(names)); err != nil {
			return err
		}
		for _, sv := range h.Services {
			if _, err := tx.Exec(`INSERT INTO services (run_id, address, port, protocol, name, product, version, tunnel, guessed)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				id, h.Address, sv.Port, sv.Protocol, sv.Name, sv.Product, sv.Version, sv.Tunnel, sv.Guessed); err != nil {
				return err
			}
		}
	}
	for _, f := range rep.Findings {
		if _, err := tx.Exec(`INSERT INTO findings (run_id, finding_id, check_id, title, severity, confidence, host, port, protocol, evidence, fix)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, f.ID, f.CheckID, f.Title, int(f.Severity), string(f.Confidence), f.Host, f.Port, f.Protocol, f.Evidence, f.Fix); err != nil {
			return err
		}
	}
	for _, e := range rep.Errors {
		if _, err := tx.Exec(`INSERT INTO check_errors (run_id, check_id, host, port, error) VALUES (?, ?, ?, ?, ?)`,
			id, e.CheckID, e.Host, e.Port, e.Error); err != nil {
			return err
		}
	}
	return nil
}

// Runs lists the newest saved runs first, at most limit of them (0 means all).
func (s *Store) Runs(limit int) ([]Summary, error) {
	if limit <= 0 {
		limit = -1 // SQLite's "no limit"
	}
	rows, err := s.db.Query(`SELECT r.id, r.name, r.kind, r.started_by, r.targets, r.status, r.started, r.finished,
			(SELECT count(*) FROM hosts h WHERE h.run_id = r.id),
			coalesce(f.info, 0), coalesce(f.low, 0), coalesce(f.medium, 0), coalesce(f.high, 0), coalesce(f.critical, 0)
		FROM runs r LEFT JOIN (
			SELECT run_id, sum(severity = 0) info, sum(severity = 1) low, sum(severity = 2) medium,
				sum(severity = 3) high, sum(severity = 4) critical
			FROM findings GROUP BY run_id
		) f ON f.run_id = r.id
		ORDER BY r.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list saved scans: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Summary
	for rows.Next() {
		var sum Summary
		var targets string
		var started, finished int64
		c := &sum.Findings
		if err := rows.Scan(&sum.ID, &sum.Name, &sum.Kind, &sum.StartedBy, &targets, &sum.Status, &started, &finished,
			&sum.Hosts, &c[model.Info], &c[model.Low], &c[model.Medium], &c[model.High], &c[model.Critical]); err != nil {
			return nil, fmt.Errorf("list saved scans: %w", err)
		}
		sum.Started, sum.Finished = fromUnix(started), fromUnix(finished)
		if err := json.Unmarshal([]byte(targets), &sum.Targets); err != nil {
			return nil, fmt.Errorf("list saved scans: %w", err)
		}
		out = append(out, sum)
	}
	return out, rows.Err()
}

// Run loads one run with its full report.
func (s *Store) Run(id int64) (Run, error) {
	r := Run{ID: id}
	var targets string
	var started, finished, repStarted, repFinished int64
	var hasReport bool
	err := s.db.QueryRow(`SELECT name, description, kind, started_by, settings, targets, status, error, started, finished,
			has_report, report_started, report_finished FROM runs WHERE id = ?`, id).
		Scan(&r.Name, &r.Description, &r.Kind, &r.StartedBy, &r.Settings, &targets, &r.Status, &r.Error, &started, &finished,
			&hasReport, &repStarted, &repFinished)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil {
		return Run{}, fmt.Errorf("load scan %d: %w", id, err)
	}
	if err := json.Unmarshal([]byte(targets), &r.Targets); err != nil {
		return Run{}, fmt.Errorf("load scan %d: %w", id, err)
	}
	r.Started, r.Finished = fromUnix(started), fromUnix(finished)
	if hasReport {
		rep := &engine.Report{Targets: r.Targets, Started: fromUnix(repStarted), Finished: fromUnix(repFinished)}
		if err := s.loadReport(id, rep); err != nil {
			return Run{}, fmt.Errorf("load scan %d: %w", id, err)
		}
		r.Report = rep
	}
	return r, nil
}

// loadReport reads the rows back in the order they were saved.
func (s *Store) loadReport(id int64, rep *engine.Report) error {
	hosts := map[string]int{} // address to index in rep.Hosts
	err := s.each(`SELECT address, hostnames FROM hosts WHERE run_id = ? ORDER BY rowid`, id, func(rows *sql.Rows) error {
		var h model.Host
		var names string
		if err := rows.Scan(&h.Address, &names); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(names), &h.Hostnames); err != nil {
			return err
		}
		hosts[h.Address] = len(rep.Hosts)
		rep.Hosts = append(rep.Hosts, h)
		return nil
	})
	if err != nil {
		return err
	}
	err = s.each(`SELECT address, port, protocol, name, product, version, tunnel, guessed FROM services WHERE run_id = ? ORDER BY rowid`, id, func(rows *sql.Rows) error {
		var addr string
		var sv model.Service
		if err := rows.Scan(&addr, &sv.Port, &sv.Protocol, &sv.Name, &sv.Product, &sv.Version, &sv.Tunnel, &sv.Guessed); err != nil {
			return err
		}
		if i, ok := hosts[addr]; ok {
			rep.Hosts[i].Services = append(rep.Hosts[i].Services, sv)
		}
		return nil
	})
	if err != nil {
		return err
	}
	rep.Findings = []model.Finding{}
	err = s.each(`SELECT finding_id, check_id, title, severity, confidence, host, port, protocol, evidence, fix FROM findings WHERE run_id = ? ORDER BY rowid`, id, func(rows *sql.Rows) error {
		var f model.Finding
		var conf string
		if err := rows.Scan(&f.ID, &f.CheckID, &f.Title, &f.Severity, &conf, &f.Host, &f.Port, &f.Protocol, &f.Evidence, &f.Fix); err != nil {
			return err
		}
		f.Confidence = model.Confidence(conf)
		rep.Findings = append(rep.Findings, f)
		return nil
	})
	if err != nil {
		return err
	}
	rep.Errors = []engine.CheckError{}
	return s.each(`SELECT check_id, host, port, error FROM check_errors WHERE run_id = ? ORDER BY rowid`, id, func(rows *sql.Rows) error {
		var e engine.CheckError
		if err := rows.Scan(&e.CheckID, &e.Host, &e.Port, &e.Error); err != nil {
			return err
		}
		rep.Errors = append(rep.Errors, e)
		return nil
	})
}

// each runs a query for one run and calls fn for every row.
func (s *Store) each(query string, id int64, fn func(*sql.Rows) error) error {
	rows, err := s.db.Query(query, id)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Times are saved as Unix nanoseconds, 0 means "not set".
func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func fromUnix(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

func orEmpty(s, empty string) string {
	if s == "" {
		return empty
	}
	return s
}
