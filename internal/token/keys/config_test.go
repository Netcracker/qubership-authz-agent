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

package keys

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestParseConfig_ReadsKeycloakAndProviders(t *testing.T) {
	doc := `{"keycloak": {"url": "https://kc.example", "requiredRealms": ["cloud-common"], "caFile": "/var/run/kc-ca.crt"},
	 "providers": [
		{"id": "external", "issuer": "https://idp.example/oidc", "audiences": ["account"], "allowMissingAud": true},
		{"id": "kubernetes", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks",
		 "caFile": "/var/run/ca.crt", "tokenFile": "/var/run/token", "audiences": ["netcracker"], "kubernetes": true}
	]}`
	want := Config{
		Keycloak: &Keycloak{URL: "https://kc.example", RequiredRealms: []string{"cloud-common"}, CAFile: "/var/run/kc-ca.crt"},
		Providers: []Provider{
			{ID: "external", Issuer: "https://idp.example/oidc", Audiences: []string{"account"}, AllowMissingAud: true},
			{ID: "kubernetes", JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks", CAFile: "/var/run/ca.crt", TokenFile: "/var/run/token", Audiences: []string{"netcracker"}, Kubernetes: true},
		},
	}
	got, err := ParseConfig([]byte(doc))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseConfig() = %+v, want %+v", got, want)
	}
}

// The marked provider is not named kubernetes, so a mark taken from the id
// fails the test.
func TestParseConfig_ReadsTheKubernetesMark(t *testing.T) {
	doc := `{"providers": [
		{"id": "k8s", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "tokenFile": "/var/run/token",
		 "audiences": ["netcracker"], "kubernetes": true},
		{"id": "idp", "issuer": "https://idp.example", "jwksUri": "https://idp.example/openid/v1/jwks", "audiences": ["netcracker"]}
	]}`
	want := Config{Providers: []Provider{
		{ID: "k8s", JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks", TokenFile: "/var/run/token", Audiences: []string{"netcracker"}, Kubernetes: true},
		{ID: "idp", Issuer: "https://idp.example", JWKSURI: "https://idp.example/openid/v1/jwks", Audiences: []string{"netcracker"}},
	}}
	got, err := ParseConfig([]byte(doc))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseConfig() = %+v, want %+v", got, want)
	}
}

func TestParseConfig_AcceptsAKeycloakWithoutProviders(t *testing.T) {
	doc := `{"keycloak": {"url": "https://kc.example"}}`
	if _, err := ParseConfig([]byte(doc)); err != nil {
		t.Errorf("ParseConfig(%s) error = %v, want none", doc, err)
	}
}

func TestParseConfig_RejectsAKeycloakThatBreaksARule(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"no url", `{"keycloak": {}}`},
		{"url that is not http", `{"keycloak": {"url": "ftp://kc.example"}}`},
		{"url without a host", `{"keycloak": {"url": "https:///auth"}}`},
		{"empty required realm", `{"keycloak": {"url": "https://kc.example", "requiredRealms": [""]}}`},
		{"required realm that is a dot segment", `{"keycloak": {"url": "https://kc.example", "requiredRealms": [".."]}}`},
		{"unknown field", `{"keycloak": {"url": "https://kc.example", "realm": "a"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.doc))
			if err == nil || !strings.Contains(err.Error(), "keycloak") && !strings.Contains(err.Error(), `"realm"`) {
				t.Errorf("ParseConfig(%s) error = %v, want an error about the keycloak object", tt.doc, err)
			}
		})
	}
}

// The file names no issuer, as a chart renders it, so the only source of the
// issuer is the token, and the fake provider serves discovery under that value.
func TestNew_TakesTheIssuerOfAMarkedProviderFromItsToken(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	fromToken := idp.srv.URL
	token := writeFile(t, "token", jwtWith(`{"iss": "`+fromToken+`"}`))
	doc, err := json.Marshal(map[string]any{"providers": []any{map[string]any{"id": "k8s",
		"tokenFile": token, "audiences": []string{"netcracker"}, "kubernetes": true}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(doc)
	if err != nil {
		t.Fatalf("ParseConfig(%s) error = %v", doc, err)
	}
	set := mustNew(t, cfg, testOptions())
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if _, err := set.Lookup(Query{Issuer: fromToken, KID: "k1"}); err != nil {
		t.Errorf("Lookup(the issuer of the token) error = %v, want none", err)
	}
	if got := cfg.Providers[0].Issuer; got != "" {
		t.Errorf("New() changed the Config of its caller: Issuer = %q, want empty", got)
	}
}

// With an unexpected iss in the token, the agent refuses every token of the
// cluster with TOKEN_ISSUER_UNKNOWN, so the reader needs the value it took and
// whether discovery still uses the token and the CA.
func TestNew_RecordsTheIssuerItTakesFromAToken(t *testing.T) {
	ca := newTLSIdP(t, ecJWK(t, "k1", nil)).caFile(t)
	tests := []struct {
		name       string
		issuer     string
		wantIgnore bool
	}{
		{"in-cluster issuer", "https://kubernetes.default.svc", false},
		{"issuer outside the cluster", "https://oidc.example/cluster", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := &infoRecorder{}
			opts := testOptions()
			opts.Log = log
			token := writeFile(t, "token", jwtWith(`{"iss": "`+tt.issuer+`"}`))
			mustNew(t, Config{Providers: []Provider{{ID: "k8s", CAFile: ca, TokenFile: token,
				Audiences: []string{"netcracker"}, Kubernetes: true}}}, opts)
			if len(log.infos) != 1 || !strings.Contains(log.infos[0], tt.issuer) || !strings.Contains(log.infos[0], `provider "k8s"`) {
				t.Fatalf("records = %q, want one that names the provider and %q", log.infos, tt.issuer)
			}
			if got := strings.Contains(log.infos[0], "ignores caFile"); got != tt.wantIgnore {
				t.Errorf("record %q says that caFile is ignored = %t, want %t", log.infos[0], got, tt.wantIgnore)
			}
		})
	}
}

// This is the provider of a standard cluster as a chart renders it. ParseConfig
// reads no token, because neither path exists here.
func TestParseConfig_ReadsAMarkedProviderWithoutAnIssuer(t *testing.T) {
	doc := `{"providers": [{"id": "k8s", "caFile": "/nonexistent/ca.crt", "tokenFile": "/nonexistent/token",
		"audiences": ["netcracker"], "kubernetes": true}]}`
	cfg, err := ParseConfig([]byte(doc))
	if err != nil {
		t.Fatalf("ParseConfig(%s) error = %v", doc, err)
	}
	if got := cfg.Providers[0].Issuer; got != "" {
		t.Errorf("Issuer = %q, want empty until New reads the token", got)
	}
}

// The same provider through New: the iss of the token is in the cluster, so
// discovery and the JWKS request both carry the token. The host of an address
// is compared without regard to case, and a port does not change it.
func TestNew_SendsTheTokenWithDiscoveryUnderAnInClusterIssuerFromIt(t *testing.T) {
	for _, fromToken := range []string{
		"https://kubernetes.default.svc",
		"https://kubernetes.default.svc.cluster.local",
		"https://KUBERNETES.default.svc:443",
	} {
		t.Run(fromToken, func(t *testing.T) {
			token := jwtWith(`{"iss": "` + fromToken + `"}`)
			set := mustNew(t, Config{Providers: []Provider{{ID: "k8s", CAFile: newTLSIdP(t, ecJWK(t, "k1", nil)).caFile(t),
				TokenFile: writeFile(t, "token", token), Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
			server := &clusterAPIServer{jwksURI: "https://10.0.0.1:6443/openid/v1/jwks",
				jwks: []byte(`{"keys": [` + string(ecJWK(t, "k1", nil)) + `]}`)}
			set.providers[fromToken].fetcher.client.Transport = server
			if err := set.Refresh(t.Context()); err != nil {
				t.Fatalf("Refresh() error = %v", err)
			}
			want := []string{"Bearer " + token, "Bearer " + token}
			if !slices.Equal(server.headers, want) {
				t.Errorf("Authorization headers = %q, want %q", server.headers, want)
			}
		})
	}
}

// Parsing cannot compare two issuers that it has not read, so New does, and the
// error names the value that the tokens hold.
func TestNew_RefusesTwoProvidersThatTakeOneIssuerFromTheirTokens(t *testing.T) {
	const fromToken = "https://kubernetes.default.svc"
	token := writeFile(t, "token", jwtWith(`{"iss": "`+fromToken+`"}`))
	entry := func(id string) map[string]any {
		return map[string]any{"id": id, "jwksUri": fromToken + "/openid/v1/jwks", "tokenFile": token,
			"audiences": []string{"netcracker"}, "kubernetes": true}
	}
	doc, err := json.Marshal(map[string]any{"providers": []any{entry("first"), entry("second")}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(doc)
	if err != nil {
		t.Fatalf("ParseConfig(%s) error = %v, want none", doc, err)
	}
	if _, err := New(cfg, testOptions()); err == nil || !strings.Contains(err.Error(), fromToken) {
		t.Errorf("New() error = %v, want one that names %q", err, fromToken)
	}
}

func TestNew_RefusesATokenWhoseIssIsNotAURL(t *testing.T) {
	token := writeFile(t, "token", jwtWith(`{"iss": "cluster-1"}`))
	_, err := New(Config{Providers: []Provider{{ID: "k8s", JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks",
		TokenFile: token, Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
	if err == nil || !strings.Contains(err.Error(), `provider "k8s" issuer`) {
		t.Errorf("New() error = %v, want one that names the issuer of the provider", err)
	}
}

// The agent cannot verify a token of this cluster without the issuer, so it does
// not start, and the error names the provider and the file.
func TestNew_FailsWithoutTheTokenThatNamesTheIssuer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	_, err := New(Config{Providers: []Provider{{ID: "k8s", JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks",
		TokenFile: path, Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
	if err == nil || !strings.Contains(err.Error(), `provider "k8s"`) || !strings.Contains(err.Error(), path) {
		t.Errorf("New() error = %v, want one that names the provider and %s", err, path)
	}
}

// The issuer of the token lies outside the cluster, as on a managed Kubernetes,
// so the token and the cluster CA are not used. The caFile holds no certificate,
// so a client that still read it fails the test, and the control is the same
// file under an in-cluster issuer.
func TestNew_SendsNoTokenToAnIssuerOutsideTheCluster(t *testing.T) {
	idp := newIdP(t, ecJWK(t, "k1", nil))
	notACertificate := writeFile(t, "ca", "not a certificate")
	provider := func(iss string) Provider {
		return Provider{ID: "k8s", CAFile: notACertificate, TokenFile: writeFile(t, "token", jwtWith(`{"iss": "`+iss+`"}`)),
			Audiences: []string{"netcracker"}, Kubernetes: true}
	}
	set := mustNew(t, Config{Providers: []Provider{provider(idp.srv.URL)}}, testOptions())
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := idp.authorization(); got != "" {
		t.Errorf("Authorization at the issuer = %q, want none", got)
	}
	inCluster := Config{Providers: []Provider{provider("https://kubernetes.default.svc")}}
	if _, err := New(inCluster, testOptions()); err == nil || !strings.Contains(err.Error(), "caFile") {
		t.Errorf("New() with an in-cluster issuer error = %v, want one that names caFile", err)
	}
}

// The caFile of the provider holds no certificate, so a client that read it
// fails New. The issuer signs with the CA in InternalCAFile, and a test has no
// CA from the system roots to connect through, so the pool itself is compared.
func TestNew_TrustsTheSystemRootsAndTheInternalCAUnderAnIssuerOutsideTheCluster(t *testing.T) {
	idp := newTLSIdP(t, ecJWK(t, "k1", nil))
	internalCA := idp.caFile(t)
	provider := Provider{ID: "k8s", CAFile: writeFile(t, "ca", "not a certificate"),
		TokenFile: writeFile(t, "token", jwtWith(`{"iss": "`+idp.srv.URL+`"}`)), Audiences: []string{"netcracker"}, Kubernetes: true}
	opts := testOptions()
	opts.InternalCAFile = internalCA
	set := mustNew(t, Config{Providers: []Provider{provider}}, opts)
	if err := set.Refresh(t.Context()); err != nil {
		t.Errorf("Refresh() with the CA of the issuer in InternalCAFile error = %v, want none", err)
	}
	pem, err := os.ReadFile(internalCA)
	if err != nil {
		t.Fatal(err)
	}
	want, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	if !want.AppendCertsFromPEM(pem) {
		t.Fatal("the CA of the test server is not a PEM certificate")
	}
	transport := set.providers[idp.srv.URL].fetcher.client.Transport.(*http.Transport)
	if got := transport.TLSClientConfig.RootCAs; !got.Equal(want) {
		t.Errorf("RootCAs differ from the system roots with the internal CA added")
	}
}

// The caFile of the provider holds the CA of the issuer and is not used here, so
// without InternalCAFile the provider does not trust the issuer.
func TestRefresh_FailsOnAnIssuerOutsideTheClusterSignedByACAItWasNotGiven(t *testing.T) {
	idp := newTLSIdP(t, ecJWK(t, "k1", nil))
	set := mustNew(t, Config{Providers: []Provider{{ID: "k8s", CAFile: idp.caFile(t),
		TokenFile: writeFile(t, "token", jwtWith(`{"iss": "`+idp.srv.URL+`"}`)), Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
	if err := set.Refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("Refresh() error = %v, want the failed check of the certificate", err)
	}
}

// The cluster CA is the caFile of the provider, so the internal CA stays out of
// the requests that an in-cluster issuer or a jwksUri sends. Each provider would
// fail New when it read the file that holds no certificate.
func TestNew_ReadsTheInternalCAOnlyForDiscoveryOutsideTheCluster(t *testing.T) {
	ca := newTLSIdP(t, ecJWK(t, "k1", nil)).caFile(t)
	tests := []struct {
		name, iss, jwksURI string
		wantErr            bool
	}{
		{"issuer outside the cluster", "https://oidc.example/cluster", "", true},
		{"in-cluster issuer", "https://kubernetes.default.svc", "", false},
		{"jwksUri", "https://oidc.example/cluster", "https://kubernetes.default.svc/openid/v1/jwks", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOptions()
			opts.InternalCAFile = writeFile(t, "internal-ca", "not a certificate")
			_, err := New(Config{Providers: []Provider{{ID: "k8s", JWKSURI: tt.jwksURI, CAFile: ca,
				TokenFile: writeFile(t, "token", jwtWith(`{"iss": "`+tt.iss+`"}`)), Audiences: []string{"netcracker"}, Kubernetes: true}}}, opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, want an error = %t", err, tt.wantErr)
			}
		})
	}
}

// The reader of this error set CERTIFICATE_FILE_PATH, and the caFile of the
// provider is not the file that failed.
func TestNew_NamesTheInternalCAFileItCannotUse(t *testing.T) {
	path := writeFile(t, "internal-ca", "not a certificate")
	opts := testOptions()
	opts.InternalCAFile = path
	_, err := New(Config{Providers: []Provider{{ID: "k8s", TokenFile: writeFile(t, "token", jwtWith(`{"iss": "https://oidc.example/cluster"}`)),
		Audiences: []string{"netcracker"}, Kubernetes: true}}}, opts)
	if err == nil || !strings.Contains(err.Error(), `provider "k8s" internal CA file `+path) {
		t.Errorf("New() error = %v, want one that names the internal CA file %s", err, path)
	}
}

// Discovery carries the token only under an https issuer, so an in-cluster name
// over http counts as any other issuer, and the token stays off that connection.
func TestNew_SendsNoTokenToAnInClusterNameOverHTTP(t *testing.T) {
	const fromToken = "http://kubernetes.default.svc"
	set := mustNew(t, Config{Providers: []Provider{{ID: "k8s", TokenFile: writeFile(t, "token", jwtWith(`{"iss": "`+fromToken+`"}`)),
		Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
	server := &clusterAPIServer{jwksURI: fromToken + "/openid/v1/jwks", jwks: []byte(`{"keys": [` + string(ecJWK(t, "k1", nil)) + `]}`)}
	set.providers[fromToken].fetcher.client.Transport = server
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if want := []string{"", ""}; !slices.Equal(server.headers, want) {
		t.Errorf("Authorization headers = %q, want %q", server.headers, want)
	}
}

// This is the cluster whose issuer cannot be reached from inside, so the file
// names the JWKS address on the API server, and that address needs the token.
func TestNew_SendsTheTokenToAnInClusterJWKSURIWhenTheIssuerIsOutsideTheCluster(t *testing.T) {
	const fromToken = "https://oidc.example/cluster"
	token := jwtWith(`{"iss": "` + fromToken + `"}`)
	set := mustNew(t, Config{Providers: []Provider{{ID: "k8s", JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks",
		CAFile: newTLSIdP(t, ecJWK(t, "k1", nil)).caFile(t), TokenFile: writeFile(t, "token", token),
		Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
	server := &clusterAPIServer{jwks: []byte(`{"keys": [` + string(ecJWK(t, "k1", nil)) + `]}`)}
	set.providers[fromToken].fetcher.client.Transport = server
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if want := []string{"Bearer " + token}; !slices.Equal(server.headers, want) {
		t.Errorf("Authorization headers = %q, want %q", server.headers, want)
	}
}

// The token for the API server grants access to that server, so a marked
// provider sends it to no other host and over no plain connection. The in-cluster
// addresses are the controls.
func TestParseConfig_LimitsTheAddressAMarkedProviderSendsItsTokenTo(t *testing.T) {
	tests := []struct {
		name    string
		jwksURI string
		want    string
	}{
		{"in-cluster name", "https://kubernetes.default.svc/openid/v1/jwks", ""},
		{"full in-cluster name, in capitals, with a port", "https://KUBERNETES.default.svc.cluster.local:443/openid/v1/jwks", ""},
		{"host outside the cluster", "https://oidc.example/jwks", "outside the cluster"},
		{"host outside the cluster over http", "http://oidc.example/jwks", "outside the cluster"},
		{"in-cluster name inside a longer host", "https://kubernetes.default.svc.example.com/jwks", "outside the cluster"},
		{"in-cluster name as user information", "https://kubernetes.default.svc@oidc.example/jwks", "outside the cluster"},
		{"in-cluster name over http", "http://kubernetes.default.svc/openid/v1/jwks", "over http"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := json.Marshal(map[string]any{"providers": []any{map[string]any{"id": "k8s", "jwksUri": tt.jwksURI,
				"tokenFile": "/var/run/token", "audiences": []string{"netcracker"}, "kubernetes": true}}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ParseConfig(doc)
			if tt.want == "" {
				if err != nil {
					t.Errorf("ParseConfig(%s) error = %v, want none", doc, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), `provider "k8s"`) {
				t.Errorf("ParseConfig(%s) error = %v, want one that names provider \"k8s\" and %q", doc, err, tt.want)
			}
		})
	}
}

// A caller that builds a Config in code gets the refusal of a parsed file. The
// token in the file is valid, so nothing else stops the provider.
func TestNew_RefusesAMarkedProviderThatSetsAnIssuer(t *testing.T) {
	const fromToken = "https://kubernetes.default.svc"
	_, err := New(Config{Providers: []Provider{{ID: "k8s", Issuer: fromToken, CAFile: writeFile(t, "ca", "unused"),
		TokenFile: writeFile(t, "token", jwtWith(`{"iss": "`+fromToken+`"}`)), Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
	if err == nil || !strings.Contains(err.Error(), "remove issuer") {
		t.Errorf("New() error = %v, want the refusal of the issuer", err)
	}
}

// The in-cluster issuer needs the token and the CA for discovery, so a missing
// CA is a mistake in the file and not a reason to drop the token.
func TestNew_RefusesAnInClusterIssuerFromATokenWithoutACA(t *testing.T) {
	token := writeFile(t, "token", jwtWith(`{"iss": "https://kubernetes.default.svc"}`))
	_, err := New(Config{Providers: []Provider{{ID: "k8s", TokenFile: token, Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
	if err == nil || !strings.Contains(err.Error(), "caFile") {
		t.Errorf("New() error = %v, want one that names caFile", err)
	}
}

// New validates the configuration too, so a caller that builds a Config in code
// and never parses a file gets the same refusal.
func TestNew_RefusesAnUnmarkedProviderThatLooksLikeKubernetes(t *testing.T) {
	_, err := New(Config{Providers: []Provider{{ID: "kubernetes", Issuer: "https://idp.example"}}}, testOptions())
	if err == nil || !strings.Contains(err.Error(), `provider "kubernetes" looks like a Kubernetes API server`) {
		t.Errorf("New() error = %v, want the refusal of the unmarked provider", err)
	}
}

// The reader holds only this text, so it names the setting that repairs the
// file and the way out for a provider that is not the API server.
func TestParseConfig_SaysHowToRepairAnUnmarkedProvider(t *testing.T) {
	_, err := ParseConfig([]byte(`{"providers": [{"id": "kubernetes", "issuer": "https://idp.example"}]}`))
	if err == nil {
		t.Fatal("ParseConfig() error = nil, want one for the unmarked provider")
	}
	for _, part := range []string{`provider "kubernetes"`, `"kubernetes": true`, "no namespace check", "another id"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("ParseConfig() error = %q, want it to name %q", err, part)
		}
	}
}

func TestParseConfig_AcceptsAnIDOfLettersDigitsDotsUnderscoresAndHyphens(t *testing.T) {
	doc := `{"providers": [{"id": "Cloud_common.v2-x", "issuer": "https://idp.example/realms/a"}]}`
	if _, err := ParseConfig([]byte(doc)); err != nil {
		t.Errorf("ParseConfig(%s) error = %v, want none", doc, err)
	}
}

// Every document puts a valid provider first and breaks one rule in the
// second, so an error that names providers[1] blames the entry at fault.
func TestParseConfig_RejectsAnEntryThatBreaksARule(t *testing.T) {
	tests := []struct {
		name  string
		entry map[string]any
	}{
		{"empty id", map[string]any{"id": "", "issuer": "https://idp.example/realms/b"}},
		{"id with a space", map[string]any{"id": "realm b", "issuer": "https://idp.example/realms/b"}},
		{"duplicate id", map[string]any{"id": "a", "issuer": "https://idp.example/realms/b"}},
		{"no issuer", map[string]any{"id": "b"}},
		{"no issuer on a marked provider without a tokenFile", map[string]any{"id": "b", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "audiences": []string{"netcracker"}, "kubernetes": true}},
		{"no issuer with a tokenFile on an unmarked provider", map[string]any{"id": "b", "jwksUri": "https://idp.example/realms/b/certs", "tokenFile": "/var/run/token"}},
		{"jwksUri without issuer", map[string]any{"id": "b", "jwksUri": "https://idp.example/realms/b/certs"}},
		{"duplicate issuer", map[string]any{"id": "b", "issuer": "https://idp.example/realms/a"}},
		{"tokenFile without jwksUri", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "tokenFile": "/var/run/token"}},
		{"tokenFile without jwksUri on another host, with a CA", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "caFile": "/var/run/ca.crt", "tokenFile": "/var/run/token"}},
		{"issuer on a marked provider", map[string]any{"id": "b", "issuer": "https://kubernetes.default.svc", "caFile": "/var/run/ca.crt", "tokenFile": "/var/run/token", "audiences": []string{"netcracker"}, "kubernetes": true}},
		{"unmarked provider named kubernetes", map[string]any{"id": "kubernetes", "issuer": "https://idp.example/realms/b"}},
		{"unmarked issuer on an in-cluster name", map[string]any{"id": "b", "issuer": "https://kubernetes.default.svc"}},
		{"unmarked jwksUri on an in-cluster name", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks"}},
		{"unmarked jwksUri on the full in-cluster name, in capitals, with a port", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "jwksUri": "https://KUBERNETES.default.svc.cluster.local:443/openid/v1/jwks"}},
		{"allowMissingAud without audiences", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "allowMissingAud": true}},
		{"kubernetes without audiences", map[string]any{"id": "b", "tokenFile": "/var/run/token", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "kubernetes": true}},
		{"kubernetes with allowMissingAud", map[string]any{"id": "b", "tokenFile": "/var/run/token", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "kubernetes": true, "audiences": []string{"netcracker"}, "allowMissingAud": true}},
		{"empty audience", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "audiences": []string{""}}},
		{"issuer that is not http", map[string]any{"id": "b", "issuer": "ftp://idp.example/realms/b"}},
		{"issuer without a host", map[string]any{"id": "b", "issuer": "https:///realms/b"}},
		{"jwksUri that is not http", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "jwksUri": "file:///etc/jwks.json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := json.Marshal(map[string]any{"providers": []any{
				map[string]any{"id": "a", "issuer": "https://idp.example/realms/a"},
				tt.entry,
			}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ParseConfig(doc)
			if err == nil || !strings.Contains(err.Error(), "providers[1]") {
				t.Errorf("ParseConfig(%s) error = %v, want an error naming providers[1]", doc, err)
			}
		})
	}
}

func TestParseConfig_RejectsADocumentThatBreaksARule(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"empty providers", `{"providers": []}`},
		{"no providers member", `{}`},
		{"unknown provider field", `{"providers": [{"id": "a", "issuer": "https://idp.example/realms/a", "required": true}]}`},
		{"unknown top-level field", `{"providers": [{"id": "a", "issuer": "https://idp.example/realms/a"}], "mode": "strict"}`},
		{"second JSON value", `{"providers": [{"id": "a", "issuer": "https://idp.example/realms/a"}]} {}`},
		{"not JSON", `providers: []`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(tt.doc)); err == nil {
				t.Errorf("ParseConfig(%s) error = nil, want an error", tt.doc)
			}
		})
	}
}

// jwtWith returns a compact JWT whose payload is the JSON text payload. The
// header and the signature are placeholders, since nothing checks them.
func jwtWith(payload string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
}

func TestIssuerOfTokenFile_ReturnsTheIssOfTheToken(t *testing.T) {
	const want = "https://kubernetes.default.svc.cluster.local"
	path := writeFile(t, "token", jwtWith(`{"iss": "`+want+`", "sub": "system:serviceaccount:ns:app"}`)+"\n")
	got, err := IssuerOfTokenFile(path)
	if err != nil {
		t.Fatalf("IssuerOfTokenFile() error = %v", err)
	}
	if got != want {
		t.Errorf("IssuerOfTokenFile() = %q, want %q", got, want)
	}
}

func TestIssuerOfTokenFile_RefusesAFileWithoutAnIssuer(t *testing.T) {
	tests := []struct {
		name, path string
	}{
		{"missing file", filepath.Join(t.TempDir(), "absent")},
		{"empty file", writeFile(t, "token", "\n")},
		{"two parts", writeFile(t, "token", strings.TrimSuffix(jwtWith(`{"iss": "https://a.example"}`), ".c2ln"))},
		{"four parts", writeFile(t, "token", jwtWith(`{"iss": "https://a.example"}`)+".c2ln")},
		{"payload that is not base64url", writeFile(t, "token", "e30.%%%.c2ln")},
		{"payload that is not JSON", writeFile(t, "token", jwtWith("not json"))},
		{"payload without iss", writeFile(t, "token", jwtWith(`{"sub": "a"}`))},
		{"ISS in place of iss", writeFile(t, "token", jwtWith(`{"ISS": "https://a.example"}`))},
		{"iss that is a number", writeFile(t, "token", jwtWith(`{"iss": 5}`))},
		{"empty iss", writeFile(t, "token", jwtWith(`{"iss": ""}`))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IssuerOfTokenFile(tt.path)
			if err == nil {
				t.Errorf("IssuerOfTokenFile(%s) = %q, want an error", tt.path, got)
			}
		})
	}
}

func TestReadConfig_ParsesTheFile(t *testing.T) {
	path := writeFile(t, "trusted-providers.json", `{"providers": [{"id": "a", "issuer": "https://idp.example/realms/a"}]}`)
	want := Config{Providers: []Provider{{ID: "a", Issuer: "https://idp.example/realms/a"}}}
	got, err := ReadConfig(path)
	if err != nil {
		t.Fatalf("ReadConfig(%s) error = %v", path, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadConfig(%s) = %+v, want %+v", path, got, want)
	}
}

func TestReadConfig_AMissingFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	if _, err := ReadConfig(path); err == nil {
		t.Errorf("ReadConfig(%s) error = nil, want an error", path)
	}
}
