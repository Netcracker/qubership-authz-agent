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

// Package server registers the HTTP routes of the agent on a Fiber app: the
// agent's own endpoints and, while the other containers of the Pod still
// talk to an OPA server, the slice of OPA's REST API they use.
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

// Options tune the routes.
type Options struct {
	// Authorization guards every /v1/data request with data.system.authz.allow,
	// as `opa run --authorization=basic` does: the request's method, path
	// segments, query parameters, and bearer token form the policy input.
	Authorization bool
	// Ready reports whether the service can answer; nil means always.
	Ready func() bool
}

// Server owns the handlers.
type Server struct {
	engine *engine.Engine
	logs   *decisionlog.Logger
	opts   Options
}

// Register adds the routes to app. The data API lives under /v1/data.
func Register(app *fiber.App, eng *engine.Engine, logs *decisionlog.Logger, opts Options) *Server {
	s := &Server{engine: eng, logs: logs, opts: opts}
	app.Get("/health", s.health)
	app.Get("/api-version", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		return c.SendString(LegacyAPIVersion)
	})
	app.Post("/access/v1/authorize", func(c *fiber.Ctx) error { return s.decide(c, []string{"authorize"}) })
	data := app.Group("/v1/data", s.authorize)
	data.Post("/*", func(c *fiber.Ctx) error { return s.decide(c, dataSegments(c)) })
	data.Put("/*", s.put)
	data.Patch("/*", s.patch)
	data.Get("/*", s.get)
	return s
}

func (s *Server) health(c *fiber.Ctx) error {
	if s.opts.Ready != nil && !s.opts.Ready() {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{"status": "unhealthy", "message": "the policy engine is not ready"})
	}
	return c.JSON(fiber.Map{"status": "healthy"})
}

// opaError writes an error body in the shape of OPA's REST API.
func opaError(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{"code": code, "message": message})
}

// authorize asks data.system.authz.allow before a data API request runs.
func (s *Server) authorize(c *fiber.Ctx) error {
	if !s.opts.Authorization {
		return c.Next()
	}
	segments := strings.Split(strings.Trim(c.Path(), "/"), "/")
	path := make([]any, len(segments))
	for i, seg := range segments {
		path[i] = strings.Clone(seg)
	}
	params := map[string]any{}
	for k, v := range c.Context().QueryArgs().All() {
		key := string(k)
		params[key] = append(asStrings(params[key]), string(v))
	}
	input := map[string]any{"method": c.Method(), "path": path, "params": params}
	if auth := c.Get(fiber.HeaderAuthorization); strings.HasPrefix(auth, "Bearer ") {
		input["identity"] = strings.Clone(strings.TrimPrefix(auth, "Bearer "))
	}
	v, ok, err := s.engine.Eval(c.UserContext(), []string{"system", "authz", "allow"}, input, nil)
	if err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	if ok && v == true {
		return c.Next()
	}
	return opaError(c, http.StatusUnauthorized, "unauthorized", "unauthorized resource access")
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
			return opaError(c, http.StatusBadRequest, "invalid_parameter", "error(s) occurred while decoding request: "+err.Error())
		}
		if len(req.Input) > 0 {
			if err := util.UnmarshalJSON(req.Input, &input); err != nil {
				return opaError(c, http.StatusBadRequest, "invalid_parameter", "error(s) occurred while decoding request: "+err.Error())
			}
		}
	}
	ndbc := builtins.NDBCache{}
	result, ok, err := s.engine.Eval(c.UserContext(), segments, input, ndbc)
	if err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	resp := fiber.Map{}
	if ok {
		resp["result"] = result
	}
	if s.logs != nil && s.logs.Enabled() {
		id := decisionlog.NewDecisionID()
		resp["decision_id"] = id
		s.logDecision(c, id, segments, input, result, ok, ndbc)
	}
	return c.JSON(resp)
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
		headers := map[string][]string{}
		all := c.GetReqHeaders()
		for _, name := range names {
			for k, values := range all {
				if strings.EqualFold(k, name) {
					copied := make([]string, len(values))
					for i, v := range values {
						copied[i] = strings.Clone(v)
					}
					headers[name] = copied
				}
			}
		}
		ev.RequestContext = &decisionlog.RequestContext{HTTP: &decisionlog.HTTPRequestContext{Headers: headers}}
	}
	s.logs.Log(ev)
}

// put stores the request body as the document, as PUT /v1/data/<path>.
func (s *Server) put(c *fiber.Ctx) error {
	segments := dataSegments(c)
	if len(segments) == 0 {
		return opaError(c, http.StatusBadRequest, "invalid_parameter", "the root document cannot be replaced")
	}
	var value any
	if err := util.UnmarshalJSON(c.Body(), &value); err != nil {
		return opaError(c, http.StatusBadRequest, "invalid_parameter", "error(s) occurred while decoding request: "+err.Error())
	}
	if err := s.engine.Put(c.UserContext(), segments, value); err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	return c.SendStatus(http.StatusNoContent)
}

// patch applies a JSON Patch document, as PATCH /v1/data/<path>; a missing
// target answers 404 so the writer can fall back to PUT.
func (s *Server) patch(c *fiber.Ctx) error {
	var ops []engine.PatchOp
	if err := util.UnmarshalJSON(c.Body(), &ops); err != nil {
		return opaError(c, http.StatusBadRequest, "invalid_parameter", "error(s) occurred while decoding request: "+err.Error())
	}
	err := s.engine.Patch(c.UserContext(), dataSegments(c), ops)
	switch {
	case err == nil:
		return c.SendStatus(http.StatusNoContent)
	case engine.IsNotFound(err):
		return opaError(c, http.StatusNotFound, "resource_not_found", err.Error())
	default:
		return opaError(c, http.StatusBadRequest, "invalid_parameter", err.Error())
	}
}

// get reads a document without evaluating rules, as GET /v1/data/<path>.
func (s *Server) get(c *fiber.Ctx) error {
	value, ok, err := s.engine.Get(c.UserContext(), dataSegments(c))
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
