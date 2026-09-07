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

// opa-embedded is a spike: OPA as a Go library behind the Fiber server of the
// Qubership core libraries, presenting the slice of OPA's REST API the agent
// Pod uses. It replaces the OPA container of the chart without any other
// change: the same arguments, the same policy and data directories, the same
// data API for pap-client, the same decision API for Envoy, the same decision
// logs for the collector.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	fiberserver "github.com/netcracker/qubership-core-lib-go-fiber-server-utils/v2"
	fibersecurity "github.com/netcracker/qubership-core-lib-go-fiber-server-utils/v2/security"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/util"
)

var logger logging.Logger

// options are the `opa run` arguments the chart passes. Flags the spike does
// not implement are accepted and ignored, so the container spec stays as it is.
type options struct {
	addr          string
	configFile    string
	ignore        string
	authorization bool
	paths         []string
}

func parseArgs(args []string) options {
	o := options{addr: "0.0.0.0:8181"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "run" || a == "--server" || a == "-s":
		case a == "--addr" || a == "-a":
			if i+1 < len(args) {
				i++
				o.addr = args[i]
			}
		case strings.HasPrefix(a, "--addr="):
			o.addr = strings.TrimPrefix(a, "--addr=")
		case a == "--config-file" || a == "-c":
			if i+1 < len(args) {
				i++
				o.configFile = args[i]
			}
		case strings.HasPrefix(a, "--config-file="):
			o.configFile = strings.TrimPrefix(a, "--config-file=")
		case strings.HasPrefix(a, "--ignore="):
			o.ignore = strings.TrimPrefix(a, "--ignore=")
		case a == "--authorization=basic":
			o.authorization = true
		case strings.HasPrefix(a, "-"):
		default:
			o.paths = append(o.paths, a)
		}
	}
	return o
}

type server struct {
	opts   options
	engine *Engine
	logs   *decisionLogger
}

func main() {
	configloader.Init(configloader.EnvPropertySource())
	serviceloader.Register(1, &fibersecurity.DummyFiberServerSecurityMiddleware{})
	logger = logging.GetLogger("opa-embedded")

	opts := parseArgs(os.Args[1:])
	engine, err := newEngine(opts.paths, opts.ignore)
	if err != nil {
		logger.Errorf("start: %v", err)
		os.Exit(1)
	}
	logs, err := newDecisionLogger(opts.configFile)
	if err != nil {
		logger.Errorf("start: %v", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go logs.run(ctx)

	app, err := fiberserver.New(fiber.Config{
		BodyLimit:             32 << 20,
		ReadTimeout:           30 * time.Second,
		DisableStartupMessage: true,
		// Values from the request outlive the handler here (store keys,
		// decision-log events), so Fiber must copy them out of its buffers.
		Immutable: true,
	}).WithPrometheus("/prometheus").Process()
	if err != nil {
		logger.Errorf("fiber: %v", err)
		os.Exit(1)
	}
	s := &server{opts: opts, engine: engine, logs: logs}
	app.Get("/health", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{}) })
	data := app.Group("/v1/data", s.authorize)
	data.Post("/*", s.decide)
	data.Put("/*", s.put)
	data.Patch("/*", s.patch)
	data.Get("/*", s.get)

	go func() {
		<-ctx.Done()
		_ = app.ShutdownWithTimeout(5 * time.Second)
	}()
	logger.Infof("opa-embedded: %d policy roots loaded from %v, listening on %s", len(engine.compiler.Modules), opts.paths, opts.addr)
	if err := app.Listen(opts.addr); err != nil {
		logger.Errorf("listen: %v", err)
		os.Exit(1)
	}
	stop()
	logs.wait()
}

// opaError writes an error body in the shape OPA's REST API uses.
func opaError(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{"code": code, "message": message})
}

// authorize mirrors `--authorization=basic --authentication=token`: every data
// API request is allowed by data.system.authz.allow, with the bearer token as
// the identity, or answered 401.
func (s *server) authorize(c *fiber.Ctx) error {
	if !s.opts.authorization {
		return c.Next()
	}
	segments := strings.Split(strings.Trim(c.Path(), "/"), "/")
	path := make([]any, len(segments))
	for i, seg := range segments {
		path[i] = seg
	}
	params := map[string][]string{}
	for k, v := range c.Context().QueryArgs().All() {
		params[string(k)] = append(params[string(k)], string(v))
	}
	input := map[string]any{"method": c.Method(), "path": path, "params": params}
	if auth := c.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		input["identity"] = strings.TrimPrefix(auth, "Bearer ")
	}
	v, ok, err := s.engine.Eval(c.UserContext(), []string{"system", "authz", "allow"}, input, builtins.NDBCache{})
	if err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	allowed := false
	if ok {
		switch d := v.(type) {
		case bool:
			allowed = d
		case map[string]any:
			allowed, _ = d["allowed"].(bool)
		}
	}
	if !allowed {
		return opaError(c, http.StatusUnauthorized, "unauthorized", "unauthorized resource access")
	}
	return c.Next()
}

// dataSegments returns the data path of the request as owned strings. Fiber
// hands out strings that alias fasthttp's request buffer, which is reused for
// the next request; a segment stored as a key in the store would be rewritten
// under our feet, which is exactly what happened before the copies were added.
func dataSegments(c *fiber.Ctx) []string {
	p := strings.Trim(c.Params("*"), "/")
	if p == "" {
		return nil
	}
	segments := strings.Split(p, "/")
	for i := range segments {
		segments[i] = strings.Clone(segments[i])
	}
	return segments
}

// decide is POST /v1/data/<path>: evaluate data.<path> with the input from
// the body and answer {"decision_id": ..., "result": ...}, the result key
// absent when the document is undefined.
func (s *server) decide(c *fiber.Ctx) error {
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
	segments := dataSegments(c)
	ndbc := builtins.NDBCache{}
	result, ok, err := s.engine.Eval(c.UserContext(), segments, input, ndbc)
	if err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	resp := map[string]any{}
	id := newDecisionID()
	if s.logs.enabled() {
		resp["decision_id"] = id
	}
	if ok {
		resp["result"] = result
	}
	s.logDecision(c, id, segments, input, result, ok, ndbc)
	out, err := json.Marshal(resp)
	if err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	c.Set("Content-Type", "application/json")
	return c.Send(append(out, '\n'))
}

func (s *server) logDecision(c *fiber.Ctx, id string, segments []string, input, result any, ok bool, ndbc builtins.NDBCache) {
	if !s.logs.enabled() {
		return
	}
	ev := event{
		Labels:      s.logs.labels,
		DecisionID:  id,
		Path:        strings.Join(segments, "/"),
		RequestedBy: c.IP(),
		Timestamp:   time.Now().UTC(),
	}
	if input != nil {
		ev.Input = &input
	}
	if ok {
		ev.Result = &result
	}
	if len(ndbc) > 0 {
		if v, err := ast.JSON(ndbc.AsValue()); err == nil {
			ev.NDBuiltinCache = &v
		}
	}
	if len(s.logs.headers) > 0 {
		rc := &requestContext{}
		rc.HTTP.Headers = map[string][]string{}
		all := c.GetReqHeaders()
		for _, want := range s.logs.headers {
			for name, values := range all {
				if strings.EqualFold(name, want) {
					rc.HTTP.Headers[want] = append(rc.HTTP.Headers[want], values...)
				}
			}
		}
		ev.RequestContext = rc
	}
	s.logs.log(ev)
}

// put is PUT /v1/data/<path>: replace the document.
func (s *server) put(c *fiber.Ctx) error {
	var value any
	if err := util.UnmarshalJSON(c.Body(), &value); err != nil {
		return opaError(c, http.StatusBadRequest, "invalid_parameter", "error(s) occurred while decoding request: "+err.Error())
	}
	if err := s.engine.Put(c.UserContext(), dataSegments(c), value); err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	return c.SendStatus(http.StatusNoContent)
}

// patch is PATCH /v1/data/<path> with a JSON Patch body.
func (s *server) patch(c *fiber.Ctx) error {
	var ops []patchOp
	if err := json.Unmarshal(c.Body(), &ops); err != nil {
		return opaError(c, http.StatusBadRequest, "invalid_parameter", "error(s) occurred while decoding request: "+err.Error())
	}
	err := s.engine.Patch(c.UserContext(), dataSegments(c), ops)
	switch {
	case err == nil:
		return c.SendStatus(http.StatusNoContent)
	case storage.IsNotFound(err):
		return opaError(c, http.StatusNotFound, "resource_not_found", err.Error())
	case errors.Is(err, errInvalidPatch):
		return opaError(c, http.StatusBadRequest, "invalid_parameter", err.Error())
	default:
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
}

// get is GET /v1/data/<path>: {"result": document}, or {} when it does not exist.
func (s *server) get(c *fiber.Ctx) error {
	v, ok, err := s.engine.Get(c.UserContext(), dataSegments(c))
	if err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	if !ok {
		return c.JSON(fiber.Map{})
	}
	return c.JSON(fiber.Map{"result": v})
}
