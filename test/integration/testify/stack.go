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

//go:build integration

package runtimetest

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// stackDriver performs the one action the suite needs that reaches past the
// agent's HTTP surface: restarting the OPA container on its own, with the rest
// of the agent left running. The Compose stack and a Kubernetes cluster do
// that differently; the tests see only this interface.
type stackDriver interface {
	// RestartOPA restarts the OPA container and returns once the stack is
	// ready for the test to poll OPA's own health endpoint.
	RestartOPA() error
}

// newStackDriver picks the driver from RUNTIME_PROFILE: `kubernetes` for the
// kind harness under test/k8s, anything else for the Compose stack.
func newStackDriver(cfg RuntimeConfig) (stackDriver, error) {
	if cfg.RuntimeProfile == "kubernetes" {
		return newKubeDriver(cfg)
	}
	return newComposeDriver(cfg)
}

// waitForHTTP200 polls rawURL until it answers 200 or the timeout passes.
func waitForHTTP200(rawURL string, timeout time.Duration, what string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(rawURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("%s did not answer 200 on %s within %s", what, rawURL, timeout)
}

// ── Compose ──────────────────────────────────────────────────────────────────

// composeDriver drives the Compose runtime stack through the docker CLI.
type composeDriver struct {
	docker             string // absolute path of the docker binary
	project            string
	papClientHealthURL string
}

// newComposeDriver resolves the docker binary once, so a missing CLI fails
// the suite setup with a clear message instead of the first restart step.
func newComposeDriver(cfg RuntimeConfig) (*composeDriver, error) {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return nil, fmt.Errorf("compose stack driver: docker CLI not found: %w", err)
	}
	return &composeDriver{
		docker:             docker,
		project:            cfg.ComposeProjectName,
		papClientHealthURL: cfg.PAPClientHealthURL,
	}, nil
}

// RestartOPA restarts the opa service and then pap-client as well: pap-client
// shares OPA's network namespace there (network_mode: "service:opa"), a
// restarted OPA gets a new one, and pap-client would stay cut off from OPA and
// from Docker's DNS until it rejoins. Waiting for pap-client's health leaves
// the tests after this one with a working pull loop.
func (d *composeDriver) RestartOPA() error {
	for _, service := range []string{"opa", "pap-client"} {
		out, err := exec.Command(d.docker, "compose", "-p", d.project, "restart", service).CombinedOutput()
		if err != nil {
			return fmt.Errorf("docker compose restart %s (project %s): %w: %s",
				service, d.project, err, strings.TrimSpace(string(out)))
		}
	}
	return waitForHTTP200(d.papClientHealthURL, 45*time.Second, "pap-client after the restart")
}

// ── Kubernetes ───────────────────────────────────────────────────────────────

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// kubeDriver talks to the API server of the cluster the suite runs in, with
// the Job's ServiceAccount token. Restarting OPA alone works the way an
// operator would do it from kubectl debug: an ephemeral container that shares
// the OPA container's PID namespace sends the process SIGTERM, and the kubelet
// restarts that container only. The OPA image has no shell, so the signal
// comes from another image; the agent's own pap-client image is on the node
// already and carries kill.
type kubeDriver struct {
	apiServer  string
	token      string
	namespace  string
	selector   string
	debugImage string
	client     *http.Client
}

func newKubeDriver(cfg RuntimeConfig) (*kubeDriver, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("RUNTIME_PROFILE=kubernetes needs KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT: the suite has to run inside the cluster")
	}
	token, err := os.ReadFile(serviceAccountDir + "/token")
	if err != nil {
		return nil, fmt.Errorf("read the service account token: %w", err)
	}
	ca, err := os.ReadFile(serviceAccountDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read the cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("%s/ca.crt holds no certificate", serviceAccountDir)
	}
	return &kubeDriver{
		apiServer:  "https://" + net.JoinHostPort(host, port),
		token:      strings.TrimSpace(string(token)),
		namespace:  cfg.KubeNamespace,
		selector:   cfg.KubeAgentSelector,
		debugImage: cfg.KubeDebugImage,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			},
		},
	}, nil
}

func (d *kubeDriver) do(method, path, contentType string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(method, d.apiServer+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// pod is the part of a Pod object the driver reads.
type pod struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Status struct {
		Phase             string `json:"phase"`
		ContainerStatuses []struct {
			Name         string `json:"name"`
			RestartCount int    `json:"restartCount"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

func (p pod) restartCount(container string) int {
	for _, c := range p.Status.ContainerStatuses {
		if c.Name == container {
			return c.RestartCount
		}
	}
	return -1
}

// agentPod returns the running Pod that matches the agent selector.
func (d *kubeDriver) agentPod() (pod, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods?labelSelector=%s", d.namespace, url.QueryEscape(d.selector))
	out, err := d.do(http.MethodGet, path, "", nil)
	if err != nil {
		return pod{}, err
	}
	var list struct {
		Items []pod `json:"items"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return pod{}, fmt.Errorf("decode the pod list: %w", err)
	}
	for _, p := range list.Items {
		if p.Status.Phase == "Running" {
			return p, nil
		}
	}
	return pod{}, fmt.Errorf("no running pod matches %q in namespace %s", d.selector, d.namespace)
}

// RestartOPA adds an ephemeral container that signals the OPA process and
// waits until the kubelet has restarted the container, which the Pod reports
// as a higher restartCount for it.
func (d *kubeDriver) RestartOPA() error {
	p, err := d.agentPod()
	if err != nil {
		return err
	}
	before := p.restartCount("opa")
	if before < 0 {
		return fmt.Errorf("pod %s has no opa container", p.Metadata.Name)
	}

	patch, err := json.Marshal(map[string]any{
		"spec": map[string]any{
			"ephemeralContainers": []map[string]any{{
				"name":                fmt.Sprintf("opa-restart-%d", time.Now().Unix()),
				"image":               d.debugImage,
				"imagePullPolicy":     "Never",
				"command":             []string{"kill", "1"},
				"targetContainerName": "opa",
			}},
		},
	})
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/ephemeralcontainers", d.namespace, p.Metadata.Name)
	if _, err := d.do(http.MethodPatch, path, "application/strategic-merge-patch+json", patch); err != nil {
		return fmt.Errorf("add the ephemeral container: %w", err)
	}

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		current, err := d.agentPod()
		if err == nil && current.Metadata.Name == p.Metadata.Name && current.restartCount("opa") > before {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("the opa container of pod %s did not restart within 60s, restartCount stayed %d",
		p.Metadata.Name, before)
}
