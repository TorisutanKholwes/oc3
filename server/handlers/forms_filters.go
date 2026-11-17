package serverhandlers

import (
	"fmt"
	"regexp"
	"strings"
)

// The filters of the historical collector, in the Args of the rest candidates
// of a form, as oc3 list filters: the server checks the strict candidates with
// the list the browser offers, which translates them the same way
// (legacyFilter in the frontend form-engine.ts).

var (
	legacyFilterProp = regexp.MustCompile(`^[.\w]+`)
	legacyFilterOp   = regexp.MustCompile(`^(>=|<=|[<>=])`)
)

// legacyFilter returns the oc3 list filters ("prop:expr") of a filter of the
// historical collector, "prop expr", as _where() reads the expression: chunks
// joined by & (all) or | (any), each negated by a leading "!", one of "empty",
// "(a,b)" (one of), ">v", "<v", "=v", a LIKE pattern when it holds a % (where _
// is any character too), or a value, equal. Several & chunks make as many oc3
// filters, which combine with AND; | chunks of values and patterns make one
// regular expression. A mix of & and |, which _where() leaves out rather than
// guess the order, filters nothing, as there; "%" alone too.
func legacyFilter(raw string) ([]string, error) {
	prop := legacyFilterProp.FindString(raw)
	if prop == "" {
		return nil, fmt.Errorf("invalid filter %q: no property", raw)
	}
	expr := strings.TrimSpace(raw[len(prop):])
	expr = strings.TrimPrefix(expr, "|")
	if expr == "" || expr == "%" || (strings.Contains(expr, "&") && strings.Contains(expr, "|")) {
		return nil, nil
	}
	if strings.Contains(expr, "|") {
		var fragments []string
		for _, chunk := range strings.Split(expr, "|") {
			if chunk == "" {
				continue
			}
			fragment, ok := legacyChunkRegex(chunk)
			if !ok {
				return nil, fmt.Errorf("unsupported filter %q: %q in an alternative", raw, chunk)
			}
			fragments = append(fragments, fragment)
		}
		return []string{prop + ":~^(" + strings.Join(fragments, "|") + ")$"}, nil
	}
	var out []string
	for _, chunk := range strings.Split(expr, "&") {
		if chunk == "" {
			continue
		}
		out = append(out, prop+":"+legacyChunk(chunk))
	}
	return out, nil
}

// legacyChunk is the oc3 filter expression of one chunk of a historical filter.
func legacyChunk(chunk string) string {
	if inner, ok := strings.CutPrefix(chunk, "!"); ok && inner != "" {
		return "!" + legacyChunk(inner)
	}
	if chunk == "empty" || chunk == "=empty" {
		return "empty"
	}
	if len(chunk) > 2 && strings.HasPrefix(chunk, "(") && strings.HasSuffix(chunk, ")") {
		return "in:" + chunk[1:len(chunk)-1]
	}
	if op := legacyFilterOp.FindString(chunk); op != "" {
		name := map[string]string{">=": "gte", "<=": "lte", ">": "gt", "<": "lt", "=": "eq"}[op]
		return name + ":" + chunk[len(op):]
	}
	value := strings.TrimPrefix(chunk, "~")
	if strings.Contains(value, "%") {
		return "~^" + likeRegex(value) + "$"
	}
	return "eq:" + value
}

// legacyChunkRegex is a value or a LIKE pattern as a fragment of regular
// expression, and false for anything else.
func legacyChunkRegex(chunk string) (string, bool) {
	if strings.HasPrefix(chunk, "!") || chunk == "empty" || strings.ContainsAny(chunk[:1], "<>=(") {
		return "", false
	}
	value := strings.TrimPrefix(chunk, "~")
	if strings.Contains(value, "%") {
		return likeRegex(value), true
	}
	return regexp.QuoteMeta(value), true
}

// likeRegex is a LIKE pattern as a regular expression: % any text, _ one
// character.
func likeRegex(pattern string) string {
	var b strings.Builder
	for _, c := range pattern {
		switch c {
		case '%':
			b.WriteString(".*")
		case '_':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

// candidatesQuery is the query of a rest candidates call made to check a strict
// input, from the Args of the input ("key = value" entries, references already
// replaced): the historical "filters" translated into oc3 "filter", the others
// kept, a key given several times sent several times.
func candidatesQuery(args []string) (map[string][]string, error) {
	query := map[string][]string{}
	for _, entry := range args {
		k, v, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "filters":
			filters, err := legacyFilter(v)
			if err != nil {
				return nil, err
			}
			query["filter"] = append(query["filter"], filters...)
		default:
			query[k] = append(query[k], v)
		}
	}
	return query, nil
}
