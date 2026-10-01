package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/hugr-lab/tresor/server/internal/store"
)

// Variables (specs/018): named strings, the secrets' rules - names, grants, conditional writes - in a namespace
// of their own. A variable is kept as a store.Secret whose params hold "value". The reference server resolves no
// references (it has no vault), so no variable of its is sensitive.

// maxVariableBytes is what the protocol says a service always accepts.
const maxVariableBytes = 64 << 10

func variableValue(sec *store.Secret) string {
	var value string
	_ = json.Unmarshal(sec.Params["value"], &value)
	return value
}

func variableDescriptor(sec *store.Secret, verbs []string) map[string]any {
	if verbs == nil {
		verbs = []string{}
	}
	return map[string]any{
		"name":        sec.Name,
		"comment":     sec.Comment,
		"owner":       sec.Owner,
		"created_at":  sec.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":  sec.UpdatedAt.UTC().Format(time.RFC3339),
		"version":     strconv.FormatInt(sec.Version, 10),
		"sensitive":   false,
		"permissions": verbs,
	}
}

func (s *Server) listVariables(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	out := []map[string]any{}
	for _, v := range s.vars.List() {
		if verbs := s.verbs(c, v); len(verbs) > 0 {
			out = append(out, variableDescriptor(v, verbs))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getVariable(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	v, verbs, ok := s.visible(w, r, c, r.PathValue("name"))
	if !ok {
		return
	}
	if !slices.Contains(verbs, "use") {
		s.refuse(w, c, "use")
		return
	}
	body := variableDescriptor(v, verbs)
	body["value"] = variableValue(v)
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(v.Version, 10)))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) putVariable(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	name := r.PathValue("name")
	if err := protocolName(name); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "the variable's name "+err.Error())
		return
	}
	var body struct {
		Value   *string `json:"value"`
		Comment *string `json:"comment"`
	}
	if err := readJSON(r, &body); err != nil || body.Value == nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "a variable is {value, comment?}")
		return
	}
	if !utf8.ValidString(*body.Value) || len(*body.Value) > maxVariableBytes {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "a variable's value is UTF-8, up to 64 KiB")
		return
	}
	value, _ := json.Marshal(*body.Value)
	now := s.now()
	s.upsert(w, r, name, func() *store.Secret {
		return &store.Secret{
			Type: "variable", Params: map[string]json.RawMessage{"value": value}, Comment: deref(body.Comment),
			Owner: c.Owner(), CreatedAt: now, UpdatedAt: now, Version: 1,
		}
	}, func(next *store.Secret) {
		next.Params = map[string]json.RawMessage{"value": value}
		if body.Comment != nil {
			next.Comment = *body.Comment
		}
	})
}
