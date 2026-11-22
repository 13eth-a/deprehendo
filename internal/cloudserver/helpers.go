// cloudserver helpers: opaque ids and the driver-boundary error checks the
// handlers need. the pgx/database-sql distinction lives here so no handler
// inspects driver types.
package cloudserver

import (
	crand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// newID builds an unguessable prefixed id (clouddb.NewID's shape; the prefix
// keeps rows readable in logs, the 16 random bytes keep ids unguessable).
// Zero-length randomness is a hard failure, never a predictable id.
func newID(prefix string) string {
	buf := make([]byte, 16)
	if _, err := crand.Read(buf); err != nil {
		panic("cloudserver: random id: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(buf)
}

// noRow reports sql.ErrNoRows without depending on which driver surfaced it.
func noRow(err error) bool { return errors.Is(err, sql.ErrNoRows) }

// isUniqueViolation reports a PostgreSQL unique-constraint conflict
// (duplicate upload under (organization_id, sha256), duplicate analysis under
// (upload_id, engine_key)).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
