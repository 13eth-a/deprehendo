// package clouddb owns the cloud's database access: the migration runner for
// db/migrations (checklist 7.57) and the identity helpers the API server and
// the deprehendo-cloud CLI share (7.5/7.12). everything here talks plain SQL
// against the §7.1 schema; no ORM layer exists in this repository.
//
// user accounts are the web auth layer's business (contract §8.2 [user]);
// this package only needs user ids, organizations and token hashes.
package clouddb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver ("pgx")
)

// open opens a connection pool. the DSN is a PostgreSQL URL or key/value
// string; the same string the CLI and the server pass to -database.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("clouddb: open database: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("clouddb: connect database: %w", err)
	}
	return db, nil
}

// NewID returns an unguessable identifier such as "org_5f1b…". plain
// lowercase hex keeps the object keys generated from ids inside the §6
// storage key regex, which restricts to [a-z0-9_-].
func NewID(prefix string) string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// A refusal to hand out ids unguessably is a hard failure; never
		// degrade to a predictable id.
		panic(fmt.Sprintf("clouddb: random id: %v", err))
	}
	return prefix + "_" + hex.EncodeToString(buf)
}

// NewToken returns a fresh personal token: the raw string the user keeps
// (rps_…) and the hash stored in personal_tokens (7.12: hashes only; a
// database dump must never yield a usable credential).
func NewToken() (raw string, hash []byte) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("clouddb: random token: %v", err))
	}
	raw = "rps_" + hex.EncodeToString(buf)
	return raw, TokenHash(raw)
}

// TokenHash is the sha256 every lookup goes through.
func TokenHash(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// CreateOrganization inserts an organization and returns its id.
func CreateOrganization(ctx context.Context, db *sql.DB, name string) (string, error) {
	id := NewID("org")
	if _, err := db.ExecContext(ctx, "INSERT INTO organizations (id, name) VALUES ($1, $2)", id, name); err != nil {
		return "", fmt.Errorf("clouddb: create organization: %w", err)
	}
	return id, nil
}

// CreateToken inserts a personal token for user+organization and returns the
// raw value exactly once.
func CreateToken(ctx context.Context, db *sql.DB, userID, orgID, description string) (string, error) {
	raw, hash := NewToken()
	if _, err := db.ExecContext(ctx, `INSERT INTO personal_tokens (id, user_id, organization_id, description, token_hash)
		VALUES ($1, $2, $3, $4, $5)`, NewID("tok"), userID, orgID, description, hash); err != nil {
		return "", fmt.Errorf("clouddb: create token: %w", err)
	}
	return raw, nil
}

// EnsureMembership adds a membership row; an existing one keeps its role.
func EnsureMembership(ctx context.Context, db *sql.DB, userID, orgID, role string) error {
	if _, err := db.ExecContext(ctx, `INSERT INTO memberships (user_id, organization_id, role)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, organization_id) DO NOTHING`, userID, orgID, role); err != nil {
		return fmt.Errorf("clouddb: add membership: %w", err)
	}
	return nil
}

// migrationFile is one discovered migration, in order.
type migrationFile struct {
	name    string
	upPath  string
	downOne string
}

// migrationsDir reads a migrations directory: NNN_name.up.sql and optional
// NNN_name.down.sql pairs, sorted by file name (the NNN_ prefix is the
// order).
func migrationsDir(dir string) ([]migrationFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("clouddb: read migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var files []migrationFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		filename := e.Name()
		if strings.HasSuffix(filename, ".down.sql") {
			// paired down files are registered with their .up.sql below.
			continue
		}
		name, ok := strings.CutSuffix(filename, ".up.sql")
		if !ok || name == "" || !cleanName(name) {
			if strings.HasSuffix(filename, ".sql") {
				return nil, fmt.Errorf("clouddb: migration file %q must be named NNN_name.up.sql", filename)
			}
			continue
		}
		files = append(files, migrationFile{name: name, upPath: filepath.Join(dir, filename)})
	}
	for i := range files {
		downpath := filepath.Join(dir, files[i].name+".down.sql")
		if info, err := os.Stat(downpath); err == nil && !info.IsDir() {
			files[i].downOne = downpath
		}
	}
	return files, nil
}

// cleanName reports whether every rune is safe for a migration filename
// table key: digits, letter, '_' and '-' only.
func cleanName(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// apply migrations from dir to the database, in file order, each in one
// transaction. applied names are recorded in schema_migrations; re-running
// applies only the pending files. it uses the pgx native connection because
// each migration file may hold several statements (pgx runs multiple
// statements in one exec when the query has no parameters).
func Apply(ctx context.Context, dsn, dir string) (applied []string, err error) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("clouddb: connect for migrations: %w", err)
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return nil, fmt.Errorf("clouddb: schema_migrations: %w", err)
	}
	files, err := migrationsDir(dir)
	if err != nil {
		return nil, err
	}
	for _, m := range files {
		var exists bool
		if err := conn.QueryRow(ctx, "SELECT true FROM schema_migrations WHERE name = $1", m.name).Scan(&exists); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("clouddb: query migration %s: %w", m.name, err)
		}
		if exists {
			continue
		}
		data, err := os.ReadFile(m.upPath)
		if err != nil {
			return nil, fmt.Errorf("clouddb: read migration %s: %w", m.name, err)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return nil, fmt.Errorf("clouddb: begin migration %s: %w", m.name, err)
		}
		// failure inside the file's own BEGIN/COMMIT rolls back both
		// transactions, but the schema_migrations insert below only follows a
		// commit of this outer one, so a failed file is never recorded.
		if _, err := tx.Exec(ctx, string(data)); err != nil {
			_ = tx.Rollback(ctx)
			return nil, fmt.Errorf("clouddb: apply migration %s: %w", m.name, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (name) VALUES ($1)", m.name); err != nil {
			_ = tx.Rollback(ctx)
			return nil, fmt.Errorf("clouddb: record migration %s: %w", m.name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("clouddb: commit migration %s: %w", m.name, err)
		}
		applied = append(applied, m.name)
	}
	return applied, nil
}

// down rolls back every applied migration in reverse order, using each
// migration's .down.sql. files without a down script stop the rollback (that
// migration cannot be undone); the list returned says what was undone.
func Down(ctx context.Context, dsn, dir string) (undone []string, err error) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("clouddb: connect for migrations: %w", err)
	}
	defer conn.Close(ctx)
	files, err := migrationsDir(dir)
	if err != nil {
		return nil, err
	}
	rows, err := conn.Query(ctx, "SELECT name FROM schema_migrations ORDER BY applied_at DESC")
	if err != nil {
		return nil, fmt.Errorf("clouddb: schema_migrations: %w", err)
	}
	var applied []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, err
		}
		applied = append(applied, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	byname := map[string]migrationFile{}
	for _, m := range files {
		byname[m.name] = m
	}
	for _, name := range applied {
		m, ok := byname[name]
		if !ok {
			return undone, fmt.Errorf("clouddb: applied migration %s is not in %s", name, dir)
		}
		if m.downOne == "" {
			return undone, fmt.Errorf("clouddb: migration %s has no down file; stopping", name)
		}
		data, err := os.ReadFile(m.downOne)
		if err != nil {
			return undone, fmt.Errorf("clouddb: read %s: %w", m.downOne, err)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return undone, fmt.Errorf("clouddb: begin rollback %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(data)); err != nil {
			_ = tx.Rollback(ctx)
			return undone, fmt.Errorf("clouddb: roll back migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, "DELETE FROM schema_migrations WHERE name = $1", name); err != nil {
			_ = tx.Rollback(ctx)
			return undone, fmt.Errorf("clouddb: record rollback %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return undone, fmt.Errorf("clouddb: commit rollback %s: %w", name, err)
		}
		undone = append(undone, name)
	}
	return undone, nil
}

// AppliedButMissing lists migration names recorded in the database that no
// longer exist in dir, a drift alarm, because a named schema state the
// runner cannot reproduce means the record lies.
func AppliedButMissing(ctx context.Context, db *sql.DB, dir string) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT name FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("clouddb: schema_migrations: %w", err)
	}
	defer rows.Close()
	files, err := migrationsDir(dir)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, m := range files {
		known[m.name] = true
	}
	var missing []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if !known[name] {
			missing = append(missing, name)
		}
	}
	return missing, rows.Err()
}
