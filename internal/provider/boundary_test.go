package provider

import (
	"go/build"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestProviderImportBoundaries enforces the 5.1 layering
// (docs/providers/architecture.md §2) over the transitive import graph:
//
//  1. the recorder (collector, platform, events) never imports any provider
//     package: recording works with no provider compiled in;
//  2. the bundle (incident) may import only the neutral evidence schema;
//  3. evidence imports only the standard library;
//  4. no internal package imports a concrete provider (anything under
//     internal/provider/ other than evidence and providertest): concrete
//     providers are wired in only by cmd/ binaries;
//  5. the analyzers (causal, diagnosis) may use the neutral provider
//     package, never a concrete provider.
func TestProviderImportBoundaries(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	module := "deprehendo"
	direct := map[string][]string{}
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, top), func(path string, info os.FileInfo, err error) error {
			if err != nil || !info.IsDir() {
				return err
			}
			pkg, err := build.ImportDir(path, 0)
			if err != nil {
				return nil // no buildable go files here
			}
			rel, _ := filepath.Rel(root, path)
			importpath := module + "/" + filepath.ToSlash(rel)
			var imports []string
			for _, imp := range pkg.Imports {
				if strings.HasPrefix(imp, module+"/") {
					imports = append(imports, imp)
				}
			}
			direct[importpath] = imports
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	closure := func(start string) map[string]bool {
		seen := map[string]bool{}
		stack := append([]string(nil), direct[start]...)
		for len(stack) > 0 {
			p := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[p] {
				continue
			}
			seen[p] = true
			stack = append(stack, direct[p]...)
		}
		return seen
	}
	const (
		neutral  = "deprehendo/internal/provider"
		schema   = "deprehendo/internal/provider/evidence"
		testkit  = "deprehendo/internal/provider/providertest"
		provRoot = "deprehendo/internal/provider/"
	)
	isconcrete := func(p string) bool {
		return strings.HasPrefix(p, provRoot) && p != schema && p != testkit
	}
	isprovider := func(p string) bool { return p == neutral || strings.HasPrefix(p, provRoot) }

	var violations []string
	for pkg := range direct {
		deps := closure(pkg)
		for dep := range deps {
			switch {
			case hasPrefixAny(pkg, "deprehendo/internal/collector", "deprehendo/internal/platform", "deprehendo/internal/events") && isprovider(dep):
				violations = append(violations, pkg+" (recorder) imports "+dep)
			case pkg == "deprehendo/internal/incident" && isprovider(dep) && dep != schema:
				violations = append(violations, pkg+" (bundle) imports "+dep+"; only the evidence schema is allowed")
			case pkg == schema:
				violations = append(violations, schema+" must import only the standard library, imports "+dep)
			case strings.HasPrefix(pkg, "deprehendo/internal/") && !strings.HasPrefix(pkg, provRoot) && pkg != neutral && isconcrete(dep):
				violations = append(violations, pkg+" imports concrete provider "+dep+"; wire providers in cmd/ only")
			case pkg == neutral && isconcrete(dep):
				violations = append(violations, "the neutral provider package imports concrete provider "+dep)
			}
		}
	}
	sort.Strings(violations)
	for _, v := range violations {
		t.Error(v)
	}
	if len(direct) < 10 {
		t.Fatalf("import walk found only %d packages; the boundary check is not looking at the module", len(direct))
	}
}

func hasPrefixAny(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if s == p || strings.HasPrefix(s, p+"/") {
			return true
		}
	}
	return false
}
