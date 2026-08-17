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

package policyadmin

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	DefaultListenAddr          = "127.0.0.1:8182"
	DefaultHealthPath          = "/health"
	DefaultPolicyFile          = "/etc/opa/data/policies.json"
	DefaultPIPFile             = "/etc/opa/data/pips.json"
	DefaultBootstrapStatusFile = "/var/run/authz/bootstrap-status.json"
	// DefaultPullStatusFile is where PolicyPuller and MountWatcher record the
	// first-pull latch.  Read by "pap-client healthcheck --readiness".
	// Lives in the same emptyDir volume as the bootstrap status file so it is
	// writable at uid 65534 without extra mounts.
	DefaultPullStatusFile = "/var/run/authz/pull-status.json"
	// DefaultM2MFile is where TokenWatcher writes the M2M bearer token so OPA
	// can reload data.m2m from disk after a restart.  Path must produce the
	// data.m2m document root when OPA loads the data directory, so the top-
	// level key in the file is "m2m" and the file sits at the root of the OPA
	// data directory (parallel to policies.json and pips.json).
	DefaultM2MFile      = "/etc/opa/data/m2m.json"
	DefaultOPAHealthURL = "http://127.0.0.1:8181/health"
	DefaultRequestLimit = 5 << 20
)

// Config holds the runtime configuration for the pap-client HTTP server.
// Policy and PIP delivery is handled by PolicyPuller (pull loop) or
// MountWatcher (ConfigMap mount) — both are wired in main.go independently
// of this service.
type Config struct {
	ListenAddr          string
	BootstrapStatusFile string
	// PullStatusFile is read (never written) by the health handler to report
	// the last conversion counts. Empty disables that part of the response.
	PullStatusFile          string
	OPAHealthURL            string
	RequestBodyLimit        int64
	HTTPClient              *http.Client
	Logger                  *log.Logger
	DecisionLogFile         string
	DecisionLogIngestPath   string
	DecisionLogDownloadPath string
}

type Service struct {
	listenAddr              string
	bootstrapStatusFile     string
	pullStatusFile          string
	opaHealthURL            string
	limit                   int64
	client                  *http.Client
	logger                  *log.Logger
	decisionLog             *decisionLogStore
	decisionLogIngestPath   string
	decisionLogDownloadPath string
}

// ErrorResponse is the standard JSON error body returned by all handlers.
type ErrorResponse struct {
	Message string `json:"message"`
}

func New(cfg Config) *Service {
	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = DefaultListenAddr
	}

	bootstrapStatusFile := strings.TrimSpace(cfg.BootstrapStatusFile)
	if bootstrapStatusFile == "" {
		bootstrapStatusFile = DefaultBootstrapStatusFile
	}

	pullStatusFile := strings.TrimSpace(cfg.PullStatusFile)
	if pullStatusFile == "" {
		pullStatusFile = DefaultPullStatusFile
	}

	opaHealthURL := strings.TrimSpace(cfg.OPAHealthURL)
	if opaHealthURL == "" {
		opaHealthURL = DefaultOPAHealthURL
	}

	limit := cfg.RequestBodyLimit
	if limit <= 0 {
		limit = DefaultRequestLimit
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "[pap-client] ", log.LstdFlags)
	}

	decisionLogFile := strings.TrimSpace(cfg.DecisionLogFile)
	if decisionLogFile == "" {
		decisionLogFile = DefaultDecisionLogFile
	}

	decisionLogIngestPath := strings.TrimSpace(cfg.DecisionLogIngestPath)
	if decisionLogIngestPath == "" {
		decisionLogIngestPath = DefaultDecisionLogIngestPath
	}

	decisionLogDownloadPath := strings.TrimSpace(cfg.DecisionLogDownloadPath)
	if decisionLogDownloadPath == "" {
		decisionLogDownloadPath = DefaultDecisionLogDownloadPath
	}

	return &Service{
		listenAddr:              listenAddr,
		bootstrapStatusFile:     bootstrapStatusFile,
		pullStatusFile:          pullStatusFile,
		opaHealthURL:            opaHealthURL,
		limit:                   limit,
		client:                  client,
		logger:                  logger,
		decisionLog:             newDecisionLogStore(decisionLogFile),
		decisionLogIngestPath:   decisionLogIngestPath,
		decisionLogDownloadPath: decisionLogDownloadPath,
	}
}

func (s *Service) ListenAddr() string {
	return s.listenAddr
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(DefaultHealthPath, s.handleHealth)
	mux.HandleFunc(s.decisionLogIngestPath, s.handleDecisionLogIngest)
	mux.HandleFunc(s.decisionLogDownloadPath, s.handleDecisionLogDownload)
	mux.HandleFunc("/", s.handleNotFound)
	return mux
}

func (s *Service) Server() *http.Server {
	return &http.Server{
		Addr:              s.serverAddr(),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func (s *Service) serverAddr() string {
	if s == nil {
		return DefaultListenAddr
	}
	return strings.TrimSpace(getOrDefault(s.listenAddr, DefaultListenAddr))
}

func (s *Service) handleNotFound(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotFound, ErrorResponse{Message: "not found"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(body); err != nil {
		http.Error(w, `{"message":"internal error"}`, http.StatusInternalServerError)
	}
}

func getOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
