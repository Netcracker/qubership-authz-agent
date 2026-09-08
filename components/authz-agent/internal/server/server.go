// Copyright 2024-2026 Netcracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package server registers the HTTP routes of the agent on Fiber apps: the
// public surface the clients call, which [Server.RegisterPublic] adds, and
// the slice of OPA's REST API the other containers of the Pod still use,
// which [Register] adds.
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/util"

	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/engine"
)

// LegacyAPIVersion is the body of GET /api-version: the specification
// versions the legacy service announces, kept byte for byte.
const LegacyAPIVersion = `{"specs":[{"specRootUrl":"/access","major":3,"minor":0,"supportedMajors":[1,2,3]},{"specRootUrl":"/api","major":1,"minor":1,"supportedMajors":[1]},{"specRootUrl":"/template","major":1,"minor":0,"supportedMajors":[1]},{"specRootUrl":"/preview","major":2,"minor":0,"supportedMajors":[1,2]}]}`

// decodeErrorPrefix opens the message of a request body OPA could not decode.
const decodeErrorPrefix = "error(s) occurred while decoding request: "

// Options tune the routes.
type Options struct {
	// Authorization guards every /v1/data request with data.system.authz.allow,
	// as `opa run --authorization=basic` does: the request's method, path
	// segments, query parameters, and bearer token form the policy input.
	// The canonical /access/v1/authorize route is guarded as
	// /v1/data/authorize under its own method, and the legacy check routes
	// as POST /v1/data/authorize.
	Authorization bool
	// Ready reports whether the service can answer; nil means always.
	Ready func() bool
	// PapClientURL is the base URL of the pap-client container, which
	// answers GET /health for the Pod while it still has one; the public
	// surface relays /health to it. Empty makes the public /health the
	// service's own.
	PapClientURL string
	// CollectorURL is the base URL of the decision-log collector, which
	// serves the download of the decisions it received; the public surface
	// relays GET /internal/v1/decision-logs to it. Empty leaves the download
	// unregistered.
	CollectorURL string
}

// Server owns the handlers.
type Server struct {
	engine *engine.Engine
	logs   *decisionlog.Logger
	opts   Options
}

// Register adds the routes of the OPA-compatible surface to app: /health,
// /api-version, the canonical POST /access/v1/authorize, and the data API
// under /v1/data.
func Register(app *fiber.App, eng *engine.Engine, logs *decisionlog.Logger, opts Options) *Server {
	s := &Server{engine: eng, logs: logs, opts: opts}
	app.Get("/health", s.health)
	app.Get("/api-version", apiVersion)
	app.Post("/access/v1/authorize", s.canonical)
	data := app.Group("/v1/data", s.authorize)
	data.Post("/*", func(c *fiber.Ctx) error { return s.decide(c, dataSegments(c)) })
	data.Put("/*", func(c *fiber.Ctx) error { return s.put(c, dataSegments(c)) })
	data.Patch("/*", func(c *fiber.Ctx) error { return s.patch(c, dataSegments(c)) })
	data.Get("/*", func(c *fiber.Ctx) error { return s.get(c, dataSegments(c)) })
	return s
}

func (s *Server) health(c *fiber.Ctx) error {
	if s.opts.Ready != nil && !s.opts.Ready() {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{"status": "unhealthy", "message": "the policy engine is not ready"})
	}
	return c.JSON(fiber.Map{"status": "healthy"})
}

func apiVersion(c *fiber.Ctx) error {
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.SendString(LegacyAPIVersion)
}

// opaError writes an error body in the shape of OPA's REST API.
func opaError(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{"code": code, "message": message})
}

// authorize is the /v1/data middleware: the request proceeds only when
// data.system.authz.allow permits it at its own path.
func (s *Server) authorize(c *fiber.Ctx) error {
	if !s.permitted(c, c.Method(), strings.Split(strings.Trim(c.Path(), "/"), "/")) {
		return nil
	}
	return c.Next()
}

// permitted evaluates data.system.authz.allow for the request as a data API
// request with the given method at path, with the request's query
// parameters and bearer token. It writes the refusal when the policy denies
// the request, 401 in the shape of OPA's REST API, or 500 when the policy
// failed, and returns false. Without Options.Authorization every request is
// permitted.
func (s *Server) permitted(c *fiber.Ctx, method string, path []string) bool {
	if !s.opts.Authorization {
		return true
	}
	segments := make([]any, len(path))
	for i, seg := range path {
		segments[i] = strings.Clone(seg)
	}
	params := map[string]any{}
	for k, v := range c.Context().QueryArgs().All() {
		key := string(k)
		params[key] = append(asStrings(params[key]), string(v))
	}
	input := map[string]any{"method": method, "path": segments, "params": params}
	if auth := c.Get(fiber.HeaderAuthorization); strings.HasPrefix(auth, "Bearer ") {
		input["identity"] = strings.Clone(strings.TrimPrefix(auth, "Bearer "))
	}
	v, ok, err := s.engine.Eval(c.UserContext(), []string{"system", "authz", "allow"}, input, nil)
	switch {
	case err != nil:
		_ = opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	case ok && v == true:
		return true
	default:
		_ = opaError(c, http.StatusUnauthorized, "unauthorized", "unauthorized resource access")
	}
	return false
}

func asStrings(v any) []any {
	if list, ok := v.([]any); ok {
		return list
	}
	return nil
}

// dataSegments returns the document path after /v1/data.
func dataSegments(c *fiber.Ctx) []string {
	rest := strings.Trim(c.Params("*"), "/")
	if rest == "" {
		return nil
	}
	parts := strings.Split(rest, "/")
	for i, p := range parts {
		parts[i] = strings.Clone(p)
	}
	return parts
}

// decide evaluates the document at segments with the request body as input
// and answers as OPA's data API does: {"result": ...}, or {} when the
// document is undefined, plus a decision_id when decisions are logged.
func (s *Server) decide(c *fiber.Ctx, segments []string) error {
	var input any
	if body := bytes.TrimSpace(c.Body()); len(body) > 0 {
		var req struct {
			Input json.RawMessage `json:"input"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return opaError(c, http.StatusBadRequest, "invalid_parameter", decodeErrorPrefix+err.Error())
		}
		if len(req.Input) > 0 {
			if err := util.UnmarshalJSON(req.Input, &input); err != nil {
				return opaError(c, http.StatusBadRequest, "invalid_parameter", decodeErrorPrefix+err.Error())
			}
		}
	}
	result, defined, id, err := s.evaluate(c, segments, input)
	if err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	return c.JSON(envelope(result, defined, id))
}

// evaluate runs the decision at segments with input and, when decisions are
// logged, records it under a fresh decision id; id is "" otherwise. defined
// is false when the document is undefined.
func (s *Server) evaluate(c *fiber.Ctx, segments []string, input any) (result any, defined bool, id string, err error) {
	ndbc := builtins.NDBCache{}
	result, defined, err = s.engine.Eval(c.UserContext(), segments, input, ndbc)
	if err != nil {
		return nil, false, "", err
	}
	if s.logs != nil && s.logs.Enabled() {
		id = decisionlog.NewDecisionID()
		s.logDecision(c, id, segments, input, result, defined, ndbc)
	}
	return result, defined, id, nil
}

// envelope is the data API's answer: the result when the decision is
// defined, and the decision id when it was logged.
func envelope(result any, defined bool, id string) fiber.Map {
	resp := fiber.Map{}
	if defined {
		resp["result"] = result
	}
	if id != "" {
		resp["decision_id"] = id
	}
	return resp
}

func (s *Server) logDecision(c *fiber.Ctx, id string, segments []string, input, result any, ok bool, ndbc builtins.NDBCache) {
	ev := decisionlog.Event{
		DecisionID:  id,
		Path:        strings.Join(segments, "/"),
		RequestedBy: strings.Clone(c.IP()),
	}
	if input != nil {
		ev.Input = input
	}
	if ok {
		ev.Result = result
	}
	if len(ndbc) > 0 {
		if v, err := ast.JSON(ndbc.AsValue()); err == nil {
			ev.NDBuiltinCache = v
		}
	}
	if names := s.logs.Headers(); len(names) > 0 {
		ev.RequestContext = &decisionlog.RequestContext{HTTP: &decisionlog.HTTPRequestContext{Headers: recordedHeaders(c, names)}}
	}
	s.logs.Log(ev)
}

// recordedHeaders copies the values of the named request headers, keyed by
// the configured lowercase names, out of the request buffer.
func recordedHeaders(c *fiber.Ctx, names []string) map[string][]string {
	headers := map[string][]string{}
	all := c.GetReqHeaders()
	for _, name := range names {
		for k, values := range all {
			if !strings.EqualFold(k, name) {
				continue
			}
			copied := make([]string, len(values))
			for i, v := range values {
				copied[i] = strings.Clone(v)
			}
			headers[name] = copied
		}
	}
	return headers
}

// put stores the request body as the document at segments, as
// PUT /v1/data/<path> does.
func (s *Server) put(c *fiber.Ctx, segments []string) error {
	if len(segments) == 0 {
		return opaError(c, http.StatusBadRequest, "invalid_parameter", "the root document cannot be replaced")
	}
	var value any
	if err := util.UnmarshalJSON(c.Body(), &value); err != nil {
		return opaError(c, http.StatusBadRequest, "invalid_parameter", decodeErrorPrefix+err.Error())
	}
	if err := s.engine.Put(c.UserContext(), segments, value); err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	return c.SendStatus(http.StatusNoContent)
}

// patch applies a JSON Patch document at segments, as PATCH /v1/data/<path>
// does; a missing target answers 404 so the writer can fall back to PUT.
func (s *Server) patch(c *fiber.Ctx, segments []string) error {
	var ops []engine.PatchOp
	if err := util.UnmarshalJSON(c.Body(), &ops); err != nil {
		return opaError(c, http.StatusBadRequest, "invalid_parameter", decodeErrorPrefix+err.Error())
	}
	err := s.engine.Patch(c.UserContext(), segments, ops)
	switch {
	case err == nil:
		return c.SendStatus(http.StatusNoContent)
	case engine.IsNotFound(err):
		return opaError(c, http.StatusNotFound, "resource_not_found", err.Error())
	default:
		return opaError(c, http.StatusBadRequest, "invalid_parameter", err.Error())
	}
}

// get reads the document at segments without evaluating rules, as
// GET /v1/data/<path> does.
func (s *Server) get(c *fiber.Ctx, segments []string) error {
	value, ok, err := s.engine.Get(c.UserContext(), segments)
	if err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	if !ok {
		return c.JSON(fiber.Map{})
	}
	return c.JSON(fiber.Map{"result": value})
}

// String helps tests and logs name a server.
func (s *Server) String() string {
	return fmt.Sprintf("authz-agent server (authorization=%v)", s.opts.Authorization)
}
