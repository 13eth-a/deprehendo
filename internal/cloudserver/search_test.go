// checklist 7.25: the list query is built from a fixed column table and
// bound arguments, so the tests here are about the renderer, not a database.
package cloudserver

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// listFilterFor parses a query the way the handler does.
func listFilterFor(t *testing.T, rawQuery string) (listFilter, error) {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/incidents?"+rawQuery, nil)
	return parseListFilter(r)
}

func TestListFilterEscapesLikeMetacharacters(t *testing.T) {
	f, err := listFilterFor(t, "q=100%25+_done%5C")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.search != `100% _done\` {
		t.Fatalf("search term decoded as %q", f.search)
	}
	query, args := f.query("org_a")
	if !strings.Contains(query, `ESCAPE '\'`) {
		t.Fatalf("query does not declare the LIKE escape character:\n%s", query)
	}
	found := false
	for _, arg := range args {
		if s, ok := arg.(string); ok && strings.HasPrefix(s, "%") {
			found = true
			// A raw % or _ would turn the term into a wildcard.
			if s != `%100\% \_done\\%` {
				t.Fatalf("pattern is not escaped: %q", s)
			}
		}
	}
	if !found {
		t.Fatalf("no LIKE pattern in the arguments: %#v", args)
	}
}

func TestListFilterSearchCoversTheMetadataColumns(t *testing.T) {
	f, err := listFilterFor(t, "q=linux-03")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	query, _ := f.query("org_a")
	for _, column := range searchColumns {
		if !strings.Contains(query, "i."+column+" ILIKE") {
			t.Errorf("search does not match %s:\n%s", column, query)
		}
	}
	// one pattern, reused by every column: the argument list gains a single
	// term however many columns there are.
	if n := strings.Count(query, "$2"); n != len(searchColumns) {
		t.Errorf("pattern placeholder used %d times, want %d", n, len(searchColumns))
	}
}

func TestListFilterOrganizationIsAlwaysFirst(t *testing.T) {
	// even with every filter set, the organization predicate is the first
	// condition and the first argument (contract §2.3: filters must never
	// widen scope).
	f, err := listFilterFor(t, "runner=r&repository=repo&workflow=ci&job=build&"+
		"signature=OOM&severity=high&platform=linux&id=inc_1&q=term&from=2026-01-01&to=2026-02-01")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	query, args := f.query("org_a")
	if args[0] != "org_a" {
		t.Fatalf("first argument is %v, want the organization", args[0])
	}
	if !strings.HasPrefix(query, listColumns+" WHERE i.organization_id = $1 AND ") {
		t.Fatalf("organization predicate is not first:\n%s", query)
	}
}

func TestListFilterRejectsMalformedInput(t *testing.T) {
	for _, raw := range []string{
		"limit=abc",
		"offset=-5",
		"from=yesterday",
		"to=2026-13-01",
		"q=" + strings.Repeat("a", maxSearchTerm+1),
	} {
		if _, err := listFilterFor(t, raw); err == nil {
			t.Errorf("%q was accepted, want a client error", raw)
		}
	}
}

func TestListFilterBoundsPagingAndDates(t *testing.T) {
	f, err := listFilterFor(t, "limit=100000&offset=10&from=2026-01-01&to=2026-01-02")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.PageSize != 200 {
		t.Errorf("limit = %d, want the 200 cap", f.PageSize)
	}
	if f.Offset != 10 {
		t.Errorf("offset = %d, want 10", f.Offset)
	}
	if f.from == nil || !f.from.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("from = %v, want the start of the day", f.from)
	}
	// A bare `to` date is the whole day, so the exclusive bound is the next
	// midnight.
	if f.to == nil || !f.to.Equal(time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("to = %v, want the start of the following day", f.to)
	}
	query, args := f.query("org_a")
	if !strings.Contains(query, "i.created_at >= $2 AND i.created_at < $3") {
		t.Fatalf("date bounds not rendered:\n%s", query)
	}
	// org, from, to, limit, offset.
	if len(args) != 5 {
		t.Fatalf("arguments = %d, want 5: %#v", len(args), args)
	}
}

func TestListFilterNoFiltersStillScopesTheOrganization(t *testing.T) {
	f, err := listFilterFor(t, "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	query, args := f.query("org_a")
	if len(args) != 3 {
		t.Fatalf("arguments = %#v, want org + limit + offset", args)
	}
	if !strings.Contains(query, "WHERE i.organization_id = $1") {
		t.Fatalf("unfiltered list is not org-scoped:\n%s", query)
	}
}
