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

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"

	"authz-agent/components/authz-agent/internal/legacy"
)

// RegisterPublic adds the public routes to app: the check routes of the
// legacy access-control API translated by package legacy, /api-version,
// /health, and 404 {"message":"not found"} for every other path. Each
// answers as the Envoy container answered it. A route accepts any method, as
// the Envoy path matches did; the check routes then read the body, and the
// filter routes the query, whatever the method.
func (s *Server) RegisterPublic(app *fiber.App) {
	app.Use(s.requestID)
	app.All("/access/v1/check/resource/bulk/operations", s.checkResourceBulkOperations(false))
	app.All("/preview/v1/check/resource/bulk/operations", s.checkResourceBulkOperations(false))
	app.All("/access/v1/check/resource/bulk", s.checkResourceBulk)
	app.All("/access/v1/check/resource", s.checkResource(false))
	app.All("/access/v1/check/filter", s.checkFilter)
	app.All("/access/v2/check/resource/bulk/operations", s.checkResourceBulkOperations(true))
	app.All("/preview/v2/check/resource/bulk/operations", s.checkResourceBulkOperations(true))
	app.All("/access/v2/check/resource", s.checkResource(true))
	app.All("/access/v2/check/filter", s.checkFilter)
	app.All("/api-version", apiVersion)
	app.All("/health", s.publicHealth)
	app.Use(s.notFound)
}

// requestID gives a request without an X-Request-Id one, as Envoy did, so
// input.requestId always carries an id. The propagated context built an id
// of its own from the same missing header, so the generated id replaces it
// and the response header it was propagated into: the input, the log lines,
// and the response of one request carry one id.
func (s *Server) requestID(c *fiber.Ctx) error {
	if c.Get(fiber.HeaderXRequestID) != "" {
		return c.Next()
	}
	id := utils.UUIDv4()
	c.Request().Header.Set(fiber.HeaderXRequestID, id)
	c.Response().Header.Set(fiber.HeaderXRequestID, id)
	// A process whose context providers were never registered has no
	// propagated id for the generated one to disagree with, and the header
	// carries it there on its own; the platform's Fiber builder registers
	// them before any route runs.
	ctx, err := ctxmanager.SetContextObject(c.UserContext(), xrequestid.X_REQUEST_ID_COTEXT_NAME,
		xrequestid.NewXRequestIdContextObject(id))
	if err == nil {
		c.SetUserContext(ctx)
	}
	return c.Next()
}

func (s *Server) notFound(c *fiber.Ctx) error {
	s.opts.Log.DebugC(c.UserContext(), "no route for %s %s", c.Method(), c.Path())
	return c.Status(http.StatusNotFound).JSON(fiber.Map{"message": "not found"})
}

// publicHealth is the public surface's /health: the service's own health
// for GET, and 405 for any other method, as access-control answers.
func (s *Server) publicHealth(c *fiber.Ctx) error {
	if c.Method() != fiber.MethodGet {
		return c.Status(http.StatusMethodNotAllowed).JSON(fiber.Map{"message": "method not allowed"})
	}
	return s.health(c)
}

func (s *Server) checkResource(v2 bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		resources, err := legacy.CheckResource(c.Body())
		if err != nil {
			return s.refuse(c, err)
		}
		return s.decide(c, resources, func(result any) []byte {
			return legacy.CheckResourceResponse(result, v2)
		})
	}
}

func (s *Server) checkResourceBulk(c *fiber.Ctx) error {
	resources, ids, err := legacy.CheckResourceBulk(c.Body())
	if err != nil {
		return s.refuse(c, err)
	}
	return s.decide(c, resources, func(result any) []byte {
		return legacy.CheckResourceBulkResponse(result, ids)
	})
}

// checkResourceBulkOperations serves the v1 or v2 bulk/operations routes.
func (s *Server) checkResourceBulkOperations(v2 bool) fiber.Handler {
	parse := legacy.CheckResourceBulkOperations
	if v2 {
		parse = legacy.CheckResourceBulkOperationsV2
	}
	return func(c *fiber.Ctx) error {
		resources, entries, err := parse(c.Body())
		if err != nil {
			return s.refuse(c, err)
		}
		if len(resources) == 0 {
			// A request without a single operation has nothing to decide;
			// the Lua filter answered it without calling OPA.
			return sendJSON(c, http.StatusOK, legacy.CheckResourceBulkOperationsResponse(nil, nil, v2))
		}
		return s.decide(c, resources, func(result any) []byte {
			return legacy.CheckResourceBulkOperationsResponse(result, entries, v2)
		})
	}
}

func (s *Server) checkFilter(c *fiber.Ctx) error {
	resources, err := legacy.CheckFilter(lastQuery(c, "resourceType"), lastQuery(c, "operation"))
	if err != nil {
		return s.refuse(c, err)
	}
	return s.filter(c, resources[0])
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

// refuse writes a request the legacy API rejects before any policy runs:
// 400 with the error's message.
func (s *Server) refuse(c *fiber.Ctx, err *legacy.RequestError) error {
	s.opts.Log.DebugC(c.UserContext(), "legacy request rejected path=%s: %s", c.Path(), err.Message)
	return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": err.Message})
}

func sendJSON(c *fiber.Ctx, status int, body []byte) error {
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.Status(status).Send(body)
}
