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

package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/proxy"
	"github.com/gofiber/fiber/v2/utils"

	"authz-agent/components/authz-agent/internal/legacy"
)

// originalPathHeader records, for the decision log, the route a legacy
// request used; every legacy request is logged as the decision at
// authorize.
const originalPathHeader = "X-Authz-Original-Path"

// Relay timeouts, as the Envoy routes had them.
const (
	healthTimeout       = 5 * time.Second
	decisionLogsTimeout = 30 * time.Second
)

// RegisterPublic adds the routes the Envoy container exposed to app, with
// the same meaning: the check routes of the legacy access-control API
// translated by package legacy, the canonical authorize route as a data API
// request, /api-version, /health relayed to the pap-client of
// Options.PapClientURL, the decision-log download relayed to the collector
// of Options.CollectorURL, and 404 {"message":"not found"} for every other
// path. A route accepts any method, as the Envoy path matches did; the
// check routes then read the body, and the filter routes the query,
// whatever the method.
func (s *Server) RegisterPublic(app *fiber.App) {
	app.Use(requestID)
	if s.opts.CollectorURL != "" {
		app.All("/internal/v1/decision-logs", relay(s.opts.CollectorURL, "collector", decisionLogsTimeout))
	}
	app.All("/access/v1/authorize", s.canonical)
	app.All("/access/v1/check/resource/bulk/operations", s.checkResourceBulkOperations(false))
	app.All("/preview/v1/check/resource/bulk/operations", s.checkResourceBulkOperations(false))
	app.All("/access/v1/check/resource/bulk", s.checkResourceBulk)
	app.All("/access/v1/check/resource", s.checkResource("/access/v1/check/resource", false))
	app.All("/access/v1/check/filter", s.checkFilter("/access/v1/check/filter"))
	app.All("/access/v2/check/resource/bulk/operations", s.checkResourceBulkOperations(true))
	app.All("/preview/v2/check/resource/bulk/operations", s.checkResourceBulkOperations(true))
	app.All("/access/v2/check/resource", s.checkResource("/access/v2/check/resource", true))
	app.All("/access/v2/check/filter", s.checkFilter("/access/v2/check/filter"))
	app.All("/api-version", apiVersion)
	if s.opts.PapClientURL != "" {
		app.All("/health", relay(s.opts.PapClientURL, "pap-client", healthTimeout))
	} else {
		app.All("/health", s.publicHealth)
	}
	app.Use(notFound)
}

// requestID gives a request without an X-Request-Id one, as Envoy did, so
// input.requestId and the decision log always carry an id.
func requestID(c *fiber.Ctx) error {
	if c.Get(fiber.HeaderXRequestID) == "" {
		c.Request().Header.Set(fiber.HeaderXRequestID, utils.UUIDv4())
	}
	return c.Next()
}

func notFound(c *fiber.Ctx) error {
	return c.Status(http.StatusNotFound).JSON(fiber.Map{"message": "not found"})
}

// publicHealth is /health without a pap-client to relay to: the service's
// own health for GET, and 405 for any other method, as the pap-client
// answers.
func (s *Server) publicHealth(c *fiber.Ctx) error {
	if c.Method() != fiber.MethodGet {
		return c.Status(http.StatusMethodNotAllowed).JSON(fiber.Map{"message": "method not allowed"})
	}
	return s.health(c)
}

// relay forwards the request, path and query included, to the container
// at base, and its answer back. When the container does not answer within
// timeout, the caller gets 503 naming the container.
func relay(base, name string, timeout time.Duration) fiber.Handler {
	base = strings.TrimRight(base, "/")
	return func(c *fiber.Ctx) error {
		if err := proxy.DoTimeout(c, base+c.OriginalURL(), timeout); err != nil {
			return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{"message": name + " unavailable: " + err.Error()})
		}
		return nil
	}
}

// canonical serves /access/v1/authorize as the Envoy route did: the guard
// runs for /v1/data/authorize under the request's own method, and a POST
// that passes it is the data API decision. Any other method that passes
// the guard is 405; OPA would have read or written the document.
func (s *Server) canonical(c *fiber.Ctx) error {
	if !s.permitted(c, c.Method(), []string{"v1", "data", "authorize"}) {
		return nil
	}
	if c.Method() != fiber.MethodPost {
		return c.SendStatus(http.StatusMethodNotAllowed)
	}
	return s.decide(c, []string{"authorize"})
}

func (s *Server) checkResource(originalPath string, v2 bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		resources, err := legacy.CheckResource(c.Body())
		if err != nil {
			return refuse(c, err)
		}
		return s.check(c, originalPath, resources, func(result any) []byte {
			return legacy.CheckResourceResponse(result, v2)
		})
	}
}

func (s *Server) checkResourceBulk(c *fiber.Ctx) error {
	resources, ids, err := legacy.CheckResourceBulk(c.Body())
	if err != nil {
		return refuse(c, err)
	}
	return s.check(c, "/access/v1/check/resource/bulk", resources, func(result any) []byte {
		return legacy.CheckResourceBulkResponse(result, ids)
	})
}

// checkResourceBulkOperations serves the v1 or v2 bulk/operations routes.
// The decision log records the request's own path and query for them, so
// the access and preview routes stay apart there.
func (s *Server) checkResourceBulkOperations(v2 bool) fiber.Handler {
	parse := legacy.CheckResourceBulkOperations
	if v2 {
		parse = legacy.CheckResourceBulkOperationsV2
	}
	return func(c *fiber.Ctx) error {
		resources, entries, err := parse(c.Body())
		if err != nil {
			return refuse(c, err)
		}
		if len(resources) == 0 {
			// A request without a single operation has nothing to decide;
			// the Lua filter answered it without calling OPA.
			return sendJSON(c, http.StatusOK, legacy.CheckResourceBulkOperationsResponse(nil, nil, v2))
		}
		return s.check(c, c.OriginalURL(), resources, func(result any) []byte {
			return legacy.CheckResourceBulkOperationsResponse(result, entries, v2)
		})
	}
}

func (s *Server) checkFilter(originalPath string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		resources, err := legacy.CheckFilter(lastQuery(c, "resourceType"), lastQuery(c, "operation"))
		if err != nil {
			return refuse(c, err)
		}
		return s.check(c, originalPath, resources, legacy.FilterResponse)
	}
}

// lastQuery is the value of the last query parameter named key, "" when
// there is none.
func lastQuery(c *fiber.Ctx, key string) string {
	value := ""
	for k, v := range c.Context().QueryArgs().All() {
		if string(k) == key {
			value = string(v)
		}
	}
	return value
}

// check evaluates the canonical decision for a legacy request and writes
// the response: the body shape builds from the decision, or the authError
// as {"message": ...} with its status when the policy refused the request.
// The guard runs for the request as OPA received it, a POST at
// /v1/data/authorize with the request's query parameters, so ?explain=full
// stays refused whatever the method. An
// undefined decision gets the data API's answer, and a failed evaluation
// 500, so that both stay visible as they were through Envoy. The route is
// recorded in the decision log as originalPath.
func (s *Server) check(c *fiber.Ctx, originalPath string, resources []legacy.Resource, shape func(result any) []byte) error {
	if !s.permitted(c, fiber.MethodPost, []string{"v1", "data", "authorize"}) {
		return nil
	}
	c.Request().Header.Set(originalPathHeader, originalPath)
	input := legacy.Input(c.GetReqHeaders(), resources)
	result, defined, id, err := s.evaluate(c, []string{"authorize"}, input)
	if err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	if !defined {
		return c.JSON(envelope(nil, false, id))
	}
	if status, body, refused := legacy.AuthError(result); refused {
		return sendJSON(c, status, body)
	}
	return sendJSON(c, http.StatusOK, shape(result))
}

// refuse writes a request the legacy API rejects before any policy runs:
// 400 with the error's message.
func refuse(c *fiber.Ctx, err *legacy.RequestError) error {
	return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": err.Message})
}

func sendJSON(c *fiber.Ctx, status int, body []byte) error {
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.Status(status).Send(body)
}
