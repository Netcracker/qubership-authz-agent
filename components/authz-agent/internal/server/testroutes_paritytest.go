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

//go:build paritytest

package server

import "github.com/gofiber/fiber/v2"

// registerTestRoutes adds POST /internal/v1/pull to the internal surface. It
// loads the policies from their source and answers 204 once they are
// stored, or 502 with {"error": ...} when the load fails. A test suite calls
// it after changing the source, instead of waiting for the next pull
// interval. Without [Options.PullNow] the route is not added.
func registerTestRoutes(app *fiber.App, s *Server) {
	if s.opts.PullNow == nil {
		return
	}
	app.Post("/internal/v1/pull", s.pullNow)
}

func (s *Server) pullNow(c *fiber.Ctx) error {
	if err := s.opts.PullNow(c.UserContext()); err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}
