package serverhandlers

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestNodeSelfUpdateRefused checks a node can not change on itself what the
// rights rest on, before any lookup: the Api has no database.
func TestNodeSelfUpdateRefused(t *testing.T) {
	for _, key := range nodeSelfReadOnlyFields {
		c, rec := aiContext(http.MethodPost, "/nodes/n1", "")
		c.Set(XAuthMode, AuthModeNode)
		c.Set(XNodeID, "n1")
		_ = postNodeUpdate(c, nil, nil, context.Background(), "n1", map[string]any{key: "x", "loc_city": "Paris"})
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), key) {
			t.Errorf("%s: %d %s", key, rec.Code, rec.Body.String())
		}
	}
}
