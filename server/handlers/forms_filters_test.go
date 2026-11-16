package serverhandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestLegacyFilter(t *testing.T) {
	for raw, want := range map[string][]string{
		"mon_vmname !empty":         {"mon_vmname:!empty"},
		"mon_encap_frozen_at empty": {"mon_encap_frozen_at:empty"},
		"mon_containerstatus up":    {"mon_containerstatus:eq:up"},
		"app my_app":                {"app:eq:my_app"},
		"os_name (Linux,SunOS)":     {"os_name:in:Linux,SunOS"},
		"cpu_threads >4":            {"cpu_threads:gt:4"},
		"updated <-1d":              {"updated:lt:-1d"},
		"nodename =n1":              {"nodename:eq:n1"},
		"nodename !n1":              {"nodename:!eq:n1"},
		"nodes.nodename n1":         {"nodes.nodename:eq:n1"},
		"svcname %web%":             {"svcname:~^.*web.*$"},
		"svcname a_b.%":             {`svcname:~^a.b\..*$`},
		"svcname !%test%&!empty":    {"svcname:!~^.*test.*$", "svcname:!empty"},
		"os_name Linux|SunOS%":      {"os_name:~^(Linux|SunOS.*)$"},
		"os_name |Linux":            {"os_name:eq:Linux"},
		"svcname %":                 nil,
		"svcname ":                  nil,
		"svcname a&b|c":             nil,
	} {
		got, err := legacyFilter(raw)
		if err != nil {
			t.Errorf("legacyFilter(%q): %s", raw, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("legacyFilter(%q) = %q, want %q", raw, got, want)
		}
	}
	for raw, msg := range map[string]string{
		"os_name Linux|!SunOS": "unsupported",
		" up":                  "no property",
	} {
		if _, err := legacyFilter(raw); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("legacyFilter(%q) error = %v, want %q", raw, err, msg)
		}
	}
}

func TestCandidatesQuery(t *testing.T) {
	got, err := candidatesQuery([]string{
		"props = svc_id,node_id",
		"filters = mon_vmname !empty",
		"filters = mon_containerstatus up",
		"filter = svc_env:eq:PRD",
		"no separator",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"props":  {"svc_id,node_id"},
		"filter": {"mon_vmname:!empty", "mon_containerstatus:eq:up", "svc_env:eq:PRD"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidatesQuery = %q, want %q", got, want)
	}
	if _, err := candidatesQuery([]string{"filters = os_name a|!b"}); err == nil {
		t.Error("candidatesQuery: an untranslatable filter must fail")
	}
}

// TestValidateStrictDynamicCandidates checks the strict dynamic candidates with
// the list the browser offers: the historical filters of the Args translated,
// so a value the form filters out is refused even if the submitter sees it.
func TestValidateStrictDynamicCandidates(t *testing.T) {
	rows := []map[string]any{
		{"nodename": "n1", "node_env": "PRD"},
		{"nodename": "n2", "node_env": "DEV"},
	}
	filterable := map[string]bool{"nodename": true, "node_env": true}
	var queries [][]string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/nodes" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		queries = append(queries, q["filter"])
		if q.Get("limit") != "0" || q.Has("search") {
			http.Error(w, "unexpected query "+r.URL.RawQuery, http.StatusInternalServerError)
			return
		}
		var data []map[string]any
		for _, row := range rows {
			keep := true
			for _, f := range q["filter"] {
				prop, expr, _ := strings.Cut(f, ":")
				if !filterable[prop] {
					http.Error(w, "unknown prop", http.StatusBadRequest)
					return
				}
				keep = keep && expr == "eq:"+row[prop].(string)
			}
			if keep {
				data = append(data, row)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer api.Close()
	viper.Set("server.forms.api_url", api.URL+"/api")
	defer viper.Set("server.forms.api_url", nil)

	input := map[string]any{
		"Id":               "node",
		"Function":         "/nodes",
		"Args":             []any{"props = nodename", "filters = node_env PRD"},
		"Value":            "#nodename",
		"StrictCandidates": true,
	}
	s := &formSubmission{definition: map[string]any{"Inputs": []any{input}}}
	ctx := context.Background()

	if err := s.validateInput(ctx, map[string]any{"node": "n1"}, input); err != nil {
		t.Errorf("n1, a PRD node: %s", err)
	}
	if !slices.Equal(queries[0], []string{"node_env:eq:PRD", "nodename:eq:n1"}) {
		t.Errorf("filters sent %q", queries[0])
	}
	if err := s.validateInput(ctx, map[string]any{"node": "n2"}, input); err == nil {
		t.Error("n2, a DEV node the form filters out, is accepted")
	}
	if err := s.validateInput(ctx, map[string]any{"node": "n3"}, input); err == nil {
		t.Error("n3, an unknown node, is accepted")
	}

	// A key the list cannot filter on: refused, then the whole filtered list.
	delete(filterable, "nodename")
	queries = nil
	if err := s.validateInput(ctx, map[string]any{"node": "n1"}, input); err != nil {
		t.Errorf("n1, key not filterable: %s", err)
	}
	if len(queries) != 2 || !slices.Equal(queries[1], []string{"node_env:eq:PRD"}) {
		t.Errorf("filters sent %q", queries)
	}
	if err := s.validateInput(ctx, map[string]any{"node": "n2"}, input); err == nil {
		t.Error("n2, key not filterable: accepted")
	}
}
