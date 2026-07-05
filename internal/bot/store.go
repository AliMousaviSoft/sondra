package bot

import (
	"database/sql"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver: keeps goreleaser cross-compile cgo-free
)

// monitorSpec is the serializable definition of a monitor job — everything
// needed to resume the loop after a restart.
type monitorSpec struct {
	Domain   string
	Preset   string
	Modules  []string
	Exclude  []string
	Interval time.Duration
	OnMode   string
}

// jobRecord is a persisted job: its spec plus where to deliver results.
type jobRecord struct {
	ID        int
	Kind      string // "monitor"
	Spec      monitorSpec
	Transport string // "telegram" | "discord"
	Dest      string // telegram chat id or discord channel id
}

// store persists long-running bot jobs so a restart resumes them.
type store struct {
	db *sql.DB
}

// openStore opens (creating if needed) the SQLite job store at path.
func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS jobs (
		id           INTEGER PRIMARY KEY,
		kind         TEXT NOT NULL,
		domain       TEXT NOT NULL,
		preset       TEXT,
		modules      TEXT,
		exclude      TEXT,
		interval_sec INTEGER,
		on_mode      TEXT,
		transport    TEXT NOT NULL,
		dest         TEXT NOT NULL,
		created_at   INTEGER
	)`); err != nil {
		db.Close()
		return nil, err
	}
	return &store{db: db}, nil
}

func (s *store) close() error { return s.db.Close() }

// save upserts a job record (keyed by id).
func (s *store) save(rec jobRecord) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO jobs
		 (id, kind, domain, preset, modules, exclude, interval_sec, on_mode, transport, dest, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		rec.ID, rec.Kind, rec.Spec.Domain, rec.Spec.Preset,
		strings.Join(rec.Spec.Modules, ","), strings.Join(rec.Spec.Exclude, ","),
		int64(rec.Spec.Interval/time.Second), rec.Spec.OnMode,
		rec.Transport, rec.Dest, time.Now().Unix(),
	)
	return err
}

// delete removes a job record; a no-op if it isn't there.
func (s *store) delete(id int) error {
	_, err := s.db.Exec(`DELETE FROM jobs WHERE id = ?`, id)
	return err
}

// loadAll returns every persisted job, ordered by id.
func (s *store) loadAll() ([]jobRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, kind, domain, preset, modules, exclude, interval_sec, on_mode, transport, dest
		 FROM jobs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []jobRecord
	for rows.Next() {
		var (
			rec       jobRecord
			mods, exc string
			sec       int64
		)
		if err := rows.Scan(&rec.ID, &rec.Kind, &rec.Spec.Domain, &rec.Spec.Preset,
			&mods, &exc, &sec, &rec.Spec.OnMode, &rec.Transport, &rec.Dest); err != nil {
			return nil, err
		}
		rec.Spec.Modules = splitCSV(mods)
		rec.Spec.Exclude = splitCSV(exc)
		rec.Spec.Interval = time.Duration(sec) * time.Second
		out = append(out, rec)
	}
	return out, rows.Err()
}
