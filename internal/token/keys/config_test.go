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
	"errors"
	"io/fs"
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
		{"id": "k8s", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "caFile": "/var/run/ca.crt",
		 "tokenFile": "/var/run/token", "audiences": ["netcracker"], "kubernetes": true},
		{"id": "idp", "issuer": "https://idp.example", "jwksUri": "https://idp.example/openid/v1/jwks", "audiences": ["netcracker"]}
	]}`
	want := Config{Providers: []Provider{
		{ID: "k8s", JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks", CAFile: "/var/run/ca.crt", TokenFile: "/var/run/token", Audiences: []string{"netcracker"}, Kubernetes: true},
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
// A provider with an issuer of its own comes first, as in a file that also
// trusts an identity provider.
func TestNew_TakesTheIssuerOfAMarkedProviderFromItsToken(t *testing.T) {
	other := newIdP(t, ecJWK(t, "k2", nil))
	idp := newTLSIdP(t, ecJWK(t, "k1", nil))
	opts := testOptions()
	opts.InternalCAFile = idp.caFile(t)
	fromToken := idp.srv.URL
	token := writeFile(t, "token", jwtWith(`{"iss": "`+fromToken+`"}`))
	doc, err := json.Marshal(map[string]any{"providers": []any{map[string]any{"id": "idp", "issuer": other.srv.URL},
		map[string]any{"id": "k8s", "tokenFile": token, "audiences": []string{"netcracker"}, "kubernetes": true}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(doc)
	if err != nil {
		t.Fatalf("ParseConfig(%s) error = %v", doc, err)
	}
	set := mustNew(t, cfg, opts)
	if err := set.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if _, err := set.Lookup(Query{Issuer: fromToken, KID: "k1"}); err != nil {
		t.Errorf("Lookup(the issuer of the token) error = %v, want none", err)
	}
	if got := cfg.Providers[1].Issuer; got != "" {
		t.Errorf("New() changed the Config of its caller: Issuer = %q, want empty", got)
	}
}

// Each row gives a marked provider a token of its issuer. The record names that
// issuer, and for an issuer that is not an https in-cluster address also the
// roots that discovery trusts and the settings that would send the token.
func TestNew_RecordsTheIssuerItTakesFromAToken(t *testing.T) {
	ca := newTLSIdP(t, ecJWK(t, "k1", nil)).caFile(t)
	const outside = "that issuer is not an https address on an in-cluster name, so discovery under it sends no token and trusts "
	const remedy = "; to send the token and use caFile, set jwksUri to https://kubernetes.default.svc/openid/v1/jwks"
	tests := []struct {
		name, issuer, caFile, internalCA string
		want, wantAbsent                 []string
	}{
		{"in-cluster issuer", "https://kubernetes.default.svc", ca, ca,
			nil, []string{"not an https address", "internal CA file", "set jwksUri"}},
		{"issuer outside the cluster", "https://oidc.example/cluster", ca, ca,
			[]string{outside + "the system roots and the internal CA file " + ca + " instead of caFile" + remedy}, nil},
		{"issuer outside the cluster without an internal CA file", "https://oidc.example/cluster", ca, "",
			[]string{outside + "the system roots instead of caFile" + remedy}, nil},
		{"issuer outside the cluster without caFile", "https://oidc.example/cluster", "", "",
			[]string{outside + "the system roots; to send the token, set jwksUri to https://kubernetes.default.svc/openid/v1/jwks and caFile to the cluster CA, /var/run/secrets/tokens/kubernetes/ca.crt"},
			[]string{"instead of caFile"}},
		{"in-cluster name with a trailing dot", "https://kubernetes.default.svc.", ca, "",
			[]string{outside + "the system roots instead of caFile" + remedy}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := &infoRecorder{}
			opts := testOptions()
			opts.Log = log
			opts.InternalCAFile = tt.internalCA
			token := writeFile(t, "token", jwtWith(`{"iss": "`+tt.issuer+`"}`))
			mustNew(t, Config{Providers: []Provider{{ID: "k8s", CAFile: tt.caFile, TokenFile: token,
				Audiences: []string{"netcracker"}, Kubernetes: true}}}, opts)
			taken := `provider "k8s" takes the issuer "` + tt.issuer + `" from ` + token
			if len(log.infos) != 1 || !strings.Contains(log.infos[0], taken) {
				t.Fatalf("records = %q, want one that contains %q", log.infos, taken)
			}
			checkRecord(t, log.infos[0], tt.want, tt.wantAbsent)
		})
	}
}

// checkRecord reports each string in want that record does not contain, and
// each string in absent that record contains.
func checkRecord(t *testing.T, record string, want, absent []string) {
	t.Helper()
	for _, part := range want {
		if !strings.Contains(record, part) {
			t.Errorf("record %q, want it to name %q", record, part)
		}
	}
	for _, part := range absent {
		if strings.Contains(record, part) {
			t.Errorf("record %q, want it without %q", record, part)
		}
	}
}

// This is the provider of a standard cluster as a chart renders it. Neither
// path exists here, so a ParseConfig that read the token would fail.
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

// The provider of a standard cluster, as a chart renders it, goes through New:
// when the iss of the token is an https in-cluster address, discovery and the
// JWKS request both carry the token. The host of an address is compared
// without regard to case, and a port does not change it.
func TestNew_SendsTheTokenWithDiscoveryOnlyUnderAnInClusterIssuerFromIt(t *testing.T) {
	tests := []struct {
		fromToken string
		sent      bool
	}{
		{"https://kubernetes.default.svc", true},
		{"https://kubernetes.default.svc.cluster.local", true},
		{"https://KUBERNETES.default.svc:443", true},
		{"https://kubernetes.default.svc.", false},
		{"https://kubernetes.default.svc.example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.fromToken, func(t *testing.T) {
			token := jwtWith(`{"iss": "` + tt.fromToken + `"}`)
			set := mustNew(t, Config{Providers: []Provider{{ID: "k8s", CAFile: newTLSIdP(t, ecJWK(t, "k1", nil)).caFile(t),
				TokenFile: writeFile(t, "token", token), Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
			server := &clusterAPIServer{jwksURI: "https://10.0.0.1:6443/openid/v1/jwks",
				jwks: []byte(`{"keys": [` + string(ecJWK(t, "k1", nil)) + `]}`)}
			set.providers[tt.fromToken].fetcher.client.Transport = server
			if err := set.Refresh(t.Context()); err != nil {
				t.Fatalf("Refresh() error = %v", err)
			}
			header := ""
			if tt.sent {
				header = "Bearer " + token
			}
			if want := []string{header, header}; !slices.Equal(server.headers, want) {
				t.Errorf("Authorization headers under the issuer %s = %q, want %q", tt.fromToken, server.headers, want)
			}
		})
	}
}

// A provider whose issuer is still empty is left out of the comparison, and the
// providers after it are still compared.
func TestParseConfig_RefusesADuplicateIssuerAfterAProviderThatTakesItsIssuerFromItsToken(t *testing.T) {
	doc := `{"providers": [
		{"id": "k8s", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "caFile": "/var/run/ca.crt",
		 "tokenFile": "/var/run/token", "audiences": ["netcracker"], "kubernetes": true},
		{"id": "a", "issuer": "https://idp.example"},
		{"id": "b", "issuer": "https://idp.example"}
	]}`
	_, err := ParseConfig([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), `providers[2]: issuer "https://idp.example" is used by the earlier provider "a"`) {
		t.Errorf("ParseConfig(%s) error = %v, want the duplicate issuer of providers[2]", doc, err)
	}
}

// The entry without an issuer comes after the two that share one, so a check
// of the issuers after the loop over the entries blames the wrong one.
func TestParseConfig_NamesTheFirstEntryThatBreaksARule(t *testing.T) {
	doc := `{"providers": [{"id": "a", "issuer": "https://idp.example"}, {"id": "b", "issuer": "https://idp.example"}, {"id": "c"}]}`
	_, err := ParseConfig([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), `providers[1]: issuer "https://idp.example" is used by the earlier provider "a"`) {
		t.Errorf("ParseConfig(%s) error = %v, want the duplicate issuer of providers[1]", doc, err)
	}
}

// Parsing cannot compare two issuers that it has not read, so New does. The
// error names each provider and the token file each took the issuer from,
// because neither entry holds the value.
func TestNew_RefusesTwoMarkedProvidersThatTakeOneIssuerFromTheirTokens(t *testing.T) {
	const fromToken = "https://kubernetes.default.svc"
	first := writeFile(t, "token", jwtWith(`{"iss": "`+fromToken+`"}`))
	second := writeFile(t, "token", jwtWith(`{"iss": "`+fromToken+`"}`))
	entry := func(id, token string) Provider {
		return Provider{ID: id, JWKSURI: fromToken + "/openid/v1/jwks", CAFile: "/var/run/ca.crt", TokenFile: token,
			Audiences: []string{"netcracker"}, Kubernetes: true}
	}
	_, err := New(Config{Providers: []Provider{entry("first", first), entry("second", second)}}, testOptions())
	want := `providers[1]: provider "second" takes the issuer "` + fromToken + `" from the token in ` + second + `, as provider "first" does from ` + first + `; keep one of the two`
	if err == nil || err.Error() != want {
		t.Errorf("New() error = %v, want %s", err, want)
	}
}

// A provider without the mark on the issuer of the cluster accepts the token of
// any Pod with no namespace check, so the error names that provider as the one
// to remove, whichever of the two comes first, and names the token file the
// other one took the issuer from.
func TestNew_SaysWhichProviderToRemoveWhenAMarkedOneSharesItsIssuer(t *testing.T) {
	const outside = "https://oidc.eks.example/id/ABC"
	token := writeFile(t, "token", jwtWith(`{"iss": "`+outside+`"}`))
	unmarked := Provider{ID: "eks", Issuer: outside}
	marked := Provider{ID: "k8s", TokenFile: token, Audiences: []string{"netcracker"}, Kubernetes: true}
	tests := []struct {
		name      string
		providers []Provider
		want      string
	}{
		{"the marked provider second", []Provider{unmarked, marked},
			`providers[1]: provider "k8s" takes the issuer "` + outside + `" from the token in ` + token + `, and provider "eks" sets the same issuer; remove provider "eks"`},
		{"the marked provider first", []Provider{marked, unmarked},
			`providers[1]: provider "eks" sets the issuer "` + outside + `", which provider "k8s" takes from the token in ` + token + `; remove provider "eks"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Config{Providers: tt.providers}, testOptions())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("New() error = %v, want one that contains %s", err, tt.want)
			}
		})
	}
}

// With jwksUri the issuer is only compared with the iss of a token, so New
// takes any non-empty iss. The keys are read from jwksUri, and a token of that
// iss selects them. A real API server serves them under https:cluster-1, which
// has the https scheme and no host, and serves none under an iss without that
// scheme; the fake API server here serves them under any iss.
func TestNew_TakesAnIssuerThatIsNotAnHTTPSURLWhenTheProviderSetsAJWKSURI(t *testing.T) {
	for _, fromToken := range []string{"https:cluster-1", "cluster-1", "spiffe://cluster.local"} {
		t.Run(fromToken, func(t *testing.T) {
			set := mustNew(t, Config{Providers: []Provider{{ID: "k8s", JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks",
				CAFile: newTLSIdP(t, ecJWK(t, "k1", nil)).caFile(t), TokenFile: writeFile(t, "token", jwtWith(`{"iss": "`+fromToken+`"}`)),
				Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
			set.providers[fromToken].fetcher.client.Transport = &clusterAPIServer{jwks: []byte(`{"keys": [` + string(ecJWK(t, "k1", nil)) + `]}`)}
			if err := set.Refresh(t.Context()); err != nil {
				t.Fatalf("Refresh() error = %v", err)
			}
			if _, err := set.Lookup(Query{Issuer: fromToken, KID: "k1"}); err != nil {
				t.Errorf("Lookup(%q, k1) error = %v, want none", fromToken, err)
			}
		})
	}
}

// Discovery under an issuer that is not an https URL with a host would read the
// keys that admit Kubernetes tokens over a plain connection, or from no address
// at all, so New stops. An API server serves its keys only under an issuer with
// the https scheme, so under any other issuer the error says that jwksUri
// cannot help either. Under https:cluster-1, which has that scheme and no host,
// the API server serves its keys and discovery cannot reach them, so the error
// offers jwksUri, and caFile too where the provider has none.
func TestNew_RefusesDiscoveryUnderAnIssuerThatIsNotAnHTTPSURL(t *testing.T) {
	ca := newTLSIdP(t, ecJWK(t, "k1", nil)).caFile(t)
	const noKeys = "an API server whose issuer does not use the https scheme serves no keys, so jwksUri cannot help; " +
		"set --service-account-issuer of the API server to an https URL, or remove this provider, and the agent then refuses Kubernetes tokens"
	const viaJWKSURI = "discovery under that issuer needs an https URL with a host; " +
		"to read the keys without discovery, set jwksUri to https://kubernetes.default.svc/openid/v1/jwks"
	tests := []struct {
		name, fromToken, caFile string
		// The error after "from the token in <path>, and ".
		want string
	}{
		{"an in-cluster name over http", "http://kubernetes.default.svc", ca, noKeys},
		{"an address outside the cluster over http", "http://oidc.example/cluster", ca, noKeys},
		{"another scheme", "spiffe://cluster.local", ca, noKeys},
		{"an issuer that is not a URL, without caFile", "cluster-1", "", noKeys},
		{"an issuer that does not parse as a URL", "cluster%1", ca, noKeys},
		{"https with no host", "https:cluster-1", ca, viaJWKSURI},
		{"https with no host, without caFile", "https:cluster-1", "",
			viaJWKSURI + " and caFile to the cluster CA, /var/run/secrets/tokens/kubernetes/ca.crt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := writeFile(t, "token", jwtWith(`{"iss": "`+tt.fromToken+`"}`))
			_, err := New(Config{Providers: []Provider{{ID: "k8s", CAFile: tt.caFile, TokenFile: token,
				Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
			want := `provider "k8s" takes the issuer "` + tt.fromToken + `" from the token in ` + token + `, and ` + tt.want
			if err == nil || err.Error() != want {
				t.Errorf("New() error = %v, want %s", err, want)
			}
		})
	}
}

// The agent cannot verify a token of this cluster without the issuer, so it does
// not start, and the error names the provider and the file.
func TestNew_FailsWithoutTheTokenThatNamesTheIssuer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	_, err := New(Config{Providers: []Provider{{ID: "k8s", JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks",
		CAFile: "/var/run/ca.crt", TokenFile: path, Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
	if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), `provider "k8s"`) || !strings.Contains(err.Error(), path) {
		t.Errorf("New() error = %v, want one that wraps fs.ErrNotExist and names the provider and %s", err, path)
	}
}

// The issuer of the token lies outside the cluster, as on a managed Kubernetes,
// so the token and the cluster CA are not used. The caFile holds no certificate,
// so a client that still read it fails the test, and the control is the same
// file under an in-cluster issuer.
func TestNew_SendsNoTokenToAnIssuerOutsideTheCluster(t *testing.T) {
	idp := newTLSIdP(t, ecJWK(t, "k1", nil))
	opts := testOptions()
	opts.InternalCAFile = idp.caFile(t)
	notACertificate := writeFile(t, "ca", "not a certificate")
	provider := func(iss string) Provider {
		return Provider{ID: "k8s", CAFile: notACertificate, TokenFile: writeFile(t, "token", jwtWith(`{"iss": "`+iss+`"}`)),
			Audiences: []string{"netcracker"}, Kubernetes: true}
	}
	set := mustNew(t, Config{Providers: []Provider{provider(idp.srv.URL)}}, opts)
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

// A caFile is the only CA of the requests it serves, so a certificate that a
// CA among the system roots signed does not pass for the API server or for the
// Keycloak.
func TestNew_TrustsOnlyTheCAFileOfAMarkedProviderAndOfTheKeycloak(t *testing.T) {
	const fromToken = "https://kubernetes.default.svc"
	ca := newTLSIdP(t, ecJWK(t, "k1", nil)).caFile(t)
	pem, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	want := x509.NewCertPool()
	if !want.AppendCertsFromPEM(pem) {
		t.Fatal("the CA of the test server is not a PEM certificate")
	}
	set := mustNew(t, Config{Keycloak: &Keycloak{URL: "https://kc.example", CAFile: ca},
		Providers: []Provider{{ID: "k8s", CAFile: ca, TokenFile: writeFile(t, "token", jwtWith(`{"iss": "`+fromToken+`"}`)),
			Audiences: []string{"netcracker"}, Kubernetes: true}}}, testOptions())
	if got := set.providers[fromToken].fetcher.client.Transport.(*http.Transport).TLSClientConfig.RootCAs; !got.Equal(want) {
		t.Errorf("RootCAs of the marked provider differ from a pool of its caFile alone")
	}
	if got := set.keycloakClient.Transport.(*http.Transport).TLSClientConfig.RootCAs; !got.Equal(want) {
		t.Errorf("RootCAs of the Keycloak differ from a pool of its caFile alone")
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

// InternalCAFile is not a setting of the providers file, so the error names it
// apart from the caFile of the provider.
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
		{"in-cluster name with a trailing dot", "https://kubernetes.default.svc./openid/v1/jwks", "outside the cluster"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := json.Marshal(map[string]any{"providers": []any{map[string]any{"id": "k8s", "jwksUri": tt.jwksURI,
				"caFile": "/var/run/ca.crt", "tokenFile": "/var/run/token", "audiences": []string{"netcracker"}, "kubernetes": true}}})
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

// The certificate of the API server is signed by the cluster CA, which the
// system roots of an image do not hold, so a jwksUri without caFile would fail
// every fetch after a start that succeeded.
func TestParseConfig_RefusesAJWKSURIOfAMarkedProviderWithoutACA(t *testing.T) {
	doc := `{"providers": [{"id": "k8s", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "tokenFile": "/var/run/token",
		"audiences": ["netcracker"], "kubernetes": true}]}`
	want := `provider "k8s" sets jwksUri "https://kubernetes.default.svc/openid/v1/jwks" on the API server without caFile, and the cluster CA signs the certificate of that server; set caFile to the cluster CA, /var/run/secrets/tokens/kubernetes/ca.crt`
	if _, err := ParseConfig([]byte(doc)); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("ParseConfig(%s) error = %v, want one that contains %q", doc, err, want)
	}
}

// unmarkedWithTokenFile returns a trusted providers file with one provider
// that does not set kubernetes and sends the token at path to its jwksUri.
func unmarkedWithTokenFile(t *testing.T, path string) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]any{"providers": []any{map[string]any{"id": "idp", "issuer": "https://idp.example",
		"jwksUri": "https://idp.example/jwks", "tokenFile": path}}})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestParseConfig_RefusesTheTokenForTheAPIServerOnAnUnmarkedProvider(t *testing.T) {
	tests := []struct{ name, path string }{
		{"the token", "/var/run/secrets/tokens/kubernetes/token"},
		{"a path through another directory", "/var/run/secrets/tokens/netcracker/../kubernetes/token"},
		{"a path with a doubled slash", "/var/run/secrets/tokens/kubernetes//token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := unmarkedWithTokenFile(t, tt.path)
			if _, err := ParseConfig(doc); err == nil || !strings.Contains(err.Error(), `provider "idp" sends the token for the API server`) {
				t.Errorf("ParseConfig(%s) error = %v, want the refusal of the token for the API server", doc, err)
			}
		})
	}
}

// The working directory is /var/run, so a relative path leads to the token for
// the API server.
func TestParseConfig_RefusesARelativePathToTheTokenForTheAPIServerOnAnUnmarkedProvider(t *testing.T) {
	t.Chdir("/var/run")
	doc := unmarkedWithTokenFile(t, "secrets/tokens/kubernetes/token")
	if _, err := ParseConfig(doc); err == nil || !strings.Contains(err.Error(), `provider "idp" sends the token for the API server`) {
		t.Errorf("ParseConfig(%s) in /var/run error = %v, want the refusal of the token for the API server", doc, err)
	}
}

// The marked provider of the chart reads the token for the API server, which
// the refusal of an unmarked provider names.
func TestParseConfig_AcceptsTheTokenForTheAPIServerOnAMarkedProvider(t *testing.T) {
	doc := `{"providers": [{"id": "k8s", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks",
		"caFile": "/var/run/secrets/tokens/kubernetes/ca.crt", "tokenFile": "/var/run/secrets/tokens/kubernetes/token",
		"audiences": ["netcracker"], "kubernetes": true}]}`
	if _, err := ParseConfig([]byte(doc)); err != nil {
		t.Errorf("ParseConfig(%s) error = %v, want none", doc, err)
	}
}

// The token lies in run/secrets/tokens/kubernetes, and another one in
// run/secrets/tokens/netcracker. var-run links to run, as /var/run links to
// /run in the agent image, token-link links to the token itself, and
// elsewhere/link links to the netcracker directory, so a .. after that link
// leads to the kubernetes directory, as a read opens it. A row with a working
// directory runs from var-run.
func TestLiesUnder_FollowsSymbolicLinks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "run", "secrets", "tokens", "kubernetes")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "token")
	other := filepath.Join(root, "run", "secrets", "tokens", "netcracker", "token")
	for _, path := range []string{token, other} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("sa-token"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	varRun := filepath.Join(root, "var-run")
	linkToToken := filepath.Join(root, "token-link")
	linkToOther := filepath.Join(root, "elsewhere", "link")
	if err := os.MkdirAll(filepath.Dir(linkToOther), 0o700); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{varRun: filepath.Join(root, "run"), linkToToken: token, linkToOther: filepath.Dir(other)} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	viaLink := filepath.Join(varRun, "secrets", "tokens", "kubernetes")
	tests := []struct {
		name, wd, path, dir string
		want                bool
	}{
		{"the file under a directory reached through a link", "", token, viaLink, true},
		{"the file through a link to the directory", "", filepath.Join(viaLink, "token"), dir, true},
		{"a link to the file", "", linkToToken, viaLink, true},
		{"a .. after a link to another directory", "", linkToOther + "/../kubernetes/token", viaLink, true},
		{"a .. after a link to another directory that leads to another token", "", linkToOther + "/../netcracker/token", viaLink, false},
		{"a relative path from a working directory reached through a link", varRun, "secrets/tokens/kubernetes/token", dir, true},
		{"another token beside the directory", "", other, viaLink, false},
		{"a missing file in the directory, as written", "", filepath.Join(viaLink, "absent"), viaLink, true},
		{"a missing file reached through a link", "", filepath.Join(dir, "absent"), viaLink, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wd != "" {
				t.Chdir(tt.wd)
			}
			if got := liesUnder(tt.path, tt.dir); got != tt.want {
				t.Errorf("liesUnder(%s, %s) = %t, want %t", tt.path, tt.dir, got, tt.want)
			}
		})
	}
}

// A directory whose name only starts with kubernetes, the name of the
// directory of the token for the API server, holds another token.
func TestParseConfig_AcceptsAnotherTokenOnAnUnmarkedProvider(t *testing.T) {
	tests := []struct{ name, path string }{
		{"the token for netcracker", "/var/run/secrets/tokens/netcracker/token"},
		{"a directory whose name starts with kubernetes", "/var/run/secrets/tokens/kubernetes-idp/token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := unmarkedWithTokenFile(t, tt.path)
			if _, err := ParseConfig(doc); err != nil {
				t.Errorf("ParseConfig(%s) error = %v, want none", doc, err)
			}
		})
	}
}

// A caller that builds a Config in code gets the refusal of a parsed file. The
// token and the CA in the files are valid, so nothing else stops the provider.
func TestNew_RefusesAMarkedProviderThatSetsAnIssuer(t *testing.T) {
	const fromToken = "https://kubernetes.default.svc"
	_, err := New(Config{Providers: []Provider{{ID: "k8s", Issuer: fromToken, CAFile: newTLSIdP(t, ecJWK(t, "k1", nil)).caFile(t),
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
	if err == nil || !strings.Contains(err.Error(), "set caFile to the cluster CA, /var/run/secrets/tokens/kubernetes/ca.crt") {
		t.Errorf("New() error = %v, want one that names caFile and the file of the cluster CA", err)
	}
}

// New validates the configuration too, so a caller that builds a Config in code
// and never parses a file gets the same refusal.
func TestNew_RefusesAnUnmarkedProviderThatLooksLikeKubernetes(t *testing.T) {
	_, err := New(Config{Providers: []Provider{{ID: "kubernetes", Issuer: "https://idp.example"}}}, testOptions())
	if err == nil || !strings.Contains(err.Error(), `provider "kubernetes" has the id of a Kubernetes API server`) {
		t.Errorf("New() error = %v, want the refusal of the unmarked provider", err)
	}
}

// The reader holds only this text, so it names the field that matched and an
// entry that passes, which the test parses. That entry keeps the settings of
// the refused one that a marked provider may hold. Another id is a way out only
// when the id matched, since an address on an in-cluster name stays on the API
// server.
func TestParseConfig_SaysHowToRepairAnUnmarkedProvider(t *testing.T) {
	const (
		apiToken  = "/var/run/secrets/tokens/kubernetes/token"
		clusterCA = "/var/run/secrets/tokens/kubernetes/ca.crt"
		jwks      = "https://kubernetes.default.svc/openid/v1/jwks"
	)
	tests := []struct {
		name             string
		doc              string
		want             []string
		wantAnotherIDWay bool
		// The settings of the entry the refusal offers.
		wantJWKSURI, wantTokenFile, wantCAFile string
	}{
		{"id", `{"providers": [{"id": "kubernetes", "issuer": "https://idp.example"}]}`,
			[]string{`provider "kubernetes" has the id of a Kubernetes API server`, "no namespace check"}, true, "", apiToken, clusterCA},
		{"id without an issuer", `{"providers": [{"id": "kubernetes"}]}`,
			[]string{`provider "kubernetes" has the id of a Kubernetes API server`}, true, "", apiToken, clusterCA},
		{"id with the token of another identity provider", `{"providers": [{"id": "kubernetes", "issuer": "https://idp.example", "jwksUri": "https://idp.example/jwks", "tokenFile": "/etc/idp/token"}]}`,
			[]string{`provider "kubernetes" has the id of a Kubernetes API server`}, true, "", apiToken, clusterCA},
		{"jwksUri", `{"providers": [{"id": "idp", "issuer": "https://idp.example", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks"}]}`,
			[]string{`provider "idp" sets jwksUri "https://kubernetes.default.svc/openid/v1/jwks"`, "no namespace check"}, false, jwks, apiToken, clusterCA},
		{"jwksUri on the full in-cluster name without an issuer", `{"providers": [{"id": "idp", "jwksUri": "https://kubernetes.default.svc.cluster.local/openid/v1/jwks"}]}`,
			[]string{`provider "idp" sets jwksUri "https://kubernetes.default.svc.cluster.local/openid/v1/jwks"`}, false,
			"https://kubernetes.default.svc.cluster.local/openid/v1/jwks", apiToken, clusterCA},
		{"jwksUri on an in-cluster name over http", `{"providers": [{"id": "idp", "issuer": "https://idp.example", "jwksUri": "http://kubernetes.default.svc/openid/v1/jwks"}]}`,
			[]string{`provider "idp" sets jwksUri "http://kubernetes.default.svc/openid/v1/jwks"`}, false, jwks, apiToken, clusterCA},
		{"jwksUri on an in-cluster name with a trailing dot", `{"providers": [{"id": "idp", "issuer": "https://idp.example", "jwksUri": "https://kubernetes.default.svc./openid/v1/jwks"}]}`,
			[]string{`provider "idp" sets jwksUri "https://kubernetes.default.svc./openid/v1/jwks"`}, false, jwks, apiToken, clusterCA},
		{"issuer", `{"providers": [{"id": "idp", "issuer": "https://kubernetes.default.svc.cluster.local"}]}`,
			[]string{`provider "idp" sets issuer "https://kubernetes.default.svc.cluster.local"`, "no namespace check"}, false, "", apiToken, clusterCA},
		{"tokenFile", `{"providers": [{"id": "idp", "issuer": "https://idp.example", "jwksUri": "https://idp.example/jwks", "tokenFile": "/var/run/secrets/tokens/kubernetes/sa-token"}]}`,
			[]string{`provider "idp" sends the token for the API server in tokenFile "/var/run/secrets/tokens/kubernetes/sa-token"`, "point tokenFile at the token this provider needs"}, false,
			"", "/var/run/secrets/tokens/kubernetes/sa-token", clusterCA},
		{"the jwksUri form without the mark", `{"providers": [{"id": "kubernetes", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks",
			"caFile": "/etc/cluster/ca.crt", "tokenFile": "/var/run/secrets/tokens/kubernetes/token", "audiences": ["netcracker"]}]}`,
			[]string{`provider "kubernetes" sends the token for the API server in tokenFile "/var/run/secrets/tokens/kubernetes/token"`}, false,
			jwks, apiToken, "/etc/cluster/ca.crt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.doc))
			if err == nil {
				t.Fatalf("ParseConfig(%s) error = nil, want one for the unmarked provider", tt.doc)
			}
			for _, part := range tt.want {
				if !strings.Contains(err.Error(), part) {
					t.Errorf("ParseConfig(%s) error = %q, want it to name %q", tt.doc, err, part)
				}
			}
			if got := strings.Contains(err.Error(), "another id"); got != tt.wantAnotherIDWay {
				t.Errorf("ParseConfig(%s) error = %q offers another id = %t, want %t", tt.doc, err, got, tt.wantAnotherIDWay)
			}
			repaired := `{"providers": [` + entryAfter(t, err.Error(), "replace the entry with ") + `]}`
			cfg, err := ParseConfig([]byte(repaired))
			if err != nil {
				t.Fatalf("ParseConfig(%s) of the entry the refusal offers error = %v, want none", repaired, err)
			}
			var refused struct {
				Providers []Provider `json:"providers"`
			}
			if err := json.Unmarshal([]byte(tt.doc), &refused); err != nil {
				t.Fatal(err)
			}
			offered := cfg.Providers[0]
			if offered.ID != refused.Providers[0].ID {
				t.Errorf("entry the refusal offers, %s, has the id %q, want the id of the refused entry, %q", repaired, offered.ID, refused.Providers[0].ID)
			}
			if offered.JWKSURI != tt.wantJWKSURI || offered.TokenFile != tt.wantTokenFile || offered.CAFile != tt.wantCAFile {
				t.Errorf("entry the refusal offers, %s, has jwksUri %q, tokenFile %q, caFile %q, want %q, %q, %q", repaired,
					offered.JWKSURI, offered.TokenFile, offered.CAFile, tt.wantJWKSURI, tt.wantTokenFile, tt.wantCAFile)
			}
		})
	}
}

// entryAfter returns the JSON object in text that follows lead, and stops the
// test when there is none.
func entryAfter(t *testing.T, text, lead string) string {
	t.Helper()
	_, rest, found := strings.Cut(text, lead)
	var entry json.RawMessage
	if !found || json.NewDecoder(strings.NewReader(rest)).Decode(&entry) != nil {
		t.Fatalf("%q holds no JSON object after %q", text, lead)
	}
	return string(entry)
}

// The refusals of a jwksUri that the token may not go to name caFile too where
// the provider has none, so the provider repaired as the text says passes.
func TestParseConfig_NamesCAFileInTheRefusalsOfAJWKSURIOfAMarkedProviderWithoutIt(t *testing.T) {
	tests := []struct {
		name, jwksURI, want string
	}{
		{"host outside the cluster", "https://oidc.example/jwks",
			"set jwksUri to https://kubernetes.default.svc/openid/v1/jwks and caFile to the cluster CA, /var/run/secrets/tokens/kubernetes/ca.crt"},
		{"in-cluster name over http", "http://kubernetes.default.svc/openid/v1/jwks",
			"use https, and set caFile to the cluster CA, /var/run/secrets/tokens/kubernetes/ca.crt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := `{"providers": [{"id": "k8s", "jwksUri": "` + tt.jwksURI + `", "tokenFile": "/var/run/token", "audiences": ["netcracker"], "kubernetes": true}]}`
			if _, err := ParseConfig([]byte(doc)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ParseConfig(%s) error = %v, want one that contains %q", doc, err, tt.want)
			}
		})
	}
	repaired := `{"providers": [{"id": "k8s", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "caFile": "/var/run/secrets/tokens/kubernetes/ca.crt", "tokenFile": "/var/run/token", "audiences": ["netcracker"], "kubernetes": true}]}`
	if _, err := ParseConfig([]byte(repaired)); err != nil {
		t.Errorf("ParseConfig(%s) of the provider repaired as the refusals say error = %v, want none", repaired, err)
	}
}

// A provider that has a caFile is not told to set it, and the way out through
// discovery holds only for a token whose iss is an https URL with a host, which
// New requires there.
func TestParseConfig_NamesNoCAFileInTheRefusalsOfAJWKSURIOfAMarkedProviderWithIt(t *testing.T) {
	tests := []struct {
		name, jwksURI, want string
	}{
		{"host outside the cluster", "https://oidc.example/jwks",
			"; set jwksUri to an https address on kubernetes.default.svc or kubernetes.default.svc.cluster.local, or, where the iss of the token in tokenFile is an https URL with a host, remove jwksUri to find the keys through discovery"},
		{"in-cluster name over http", "http://kubernetes.default.svc/openid/v1/jwks", "; use https"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := `{"providers": [{"id": "k8s", "jwksUri": "` + tt.jwksURI + `", "caFile": "/etc/cluster/ca.crt", "tokenFile": "/var/run/token", "audiences": ["netcracker"], "kubernetes": true}]}`
			if _, err := ParseConfig([]byte(doc)); err == nil || !strings.HasSuffix(err.Error(), tt.want) {
				t.Errorf("ParseConfig(%s) error = %v, want one that ends with %q", doc, err, tt.want)
			}
		})
	}
}

// One text serves a provider that needs an issuer, and another a provider
// that sets kubernetes and needs the token it takes its issuer from.
func TestParseConfig_NamesTheSettingAProviderWithoutAnIssuerNeeds(t *testing.T) {
	tests := []struct {
		name, entry, want, absent string
	}{
		{"a provider without the mark", `{"id": "idp"}`,
			`provider "idp" has no issuer; set issuer to the iss of its tokens`, "tokenFile"},
		{"a provider with the mark and no tokenFile", `{"id": "k8s", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "caFile": "/c", "audiences": ["netcracker"], "kubernetes": true}`,
			`provider "k8s" sets kubernetes without tokenFile; a provider that sets kubernetes takes its issuer from the token in tokenFile, so set tokenFile to the token for the API server, /var/run/secrets/tokens/kubernetes/token`, "has no issuer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := `{"providers": [` + tt.entry + `]}`
			_, err := ParseConfig([]byte(doc))
			if err == nil || !strings.Contains(err.Error(), tt.want) || strings.Contains(err.Error(), tt.absent) {
				t.Errorf("ParseConfig(%s) error = %v, want one that contains %q and not %q", doc, err, tt.want, tt.absent)
			}
		})
	}
}

// The token for the API server comes before the missing jwksUri, so the text
// does not offer a jwksUri that would still send that token.
func TestParseConfig_RefusesTheTokenForTheAPIServerBeforeAMissingJWKSURI(t *testing.T) {
	doc := `{"providers": [{"id": "idp", "issuer": "https://idp.example", "tokenFile": "/var/run/secrets/tokens/kubernetes/token"}]}`
	_, err := ParseConfig([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), `provider "idp" sends the token for the API server`) || strings.Contains(err.Error(), "set jwksUri") {
		t.Errorf("ParseConfig(%s) error = %v, want the refusal of the token for the API server, without set jwksUri", doc, err)
	}
}

// The marked provider reads its token from a file outside the directory of
// the token for the API server, as a file written by hand may, so only the file
// itself shows that the unmarked provider would send that token. Where both
// files exist, the file a read opens decides, so a path that cleans to the
// marked token but opens another file through link-to-child/.. passes; where
// neither exists yet, the cleaned paths decide.
func TestParseConfig_RefusesTheTokenOfAMarkedProviderOnAnUnmarkedOne(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	other := filepath.Join(dir, "other")
	if err := os.MkdirAll(filepath.Join(dir, "elsewhere", "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{token, other, filepath.Join(dir, "elsewhere", "token"), filepath.Join(dir, "elsewhere", "unmounted"), filepath.Join(dir, "mounted")} {
		if err := os.WriteFile(path, []byte("sa-token"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"link": token, "link-to-child": filepath.Join(dir, "elsewhere", "child")} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	withTokenFiles := func(marked, unmarked string) Config {
		return Config{Providers: []Provider{
			{ID: "k8s", JWKSURI: "https://kubernetes.default.svc/openid/v1/jwks", CAFile: "/var/run/ca.crt", TokenFile: marked,
				Audiences: []string{"netcracker"}, Kubernetes: true},
			{ID: "idp", Issuer: "https://idp.example", JWKSURI: "http://idp.example/jwks", TokenFile: unmarked},
		}}
	}
	refused := []struct{ name, marked, unmarked string }{
		{"the same path", token, token},
		{"a link to the file", token, filepath.Join(dir, "link")},
		{"the same file with a dot segment", token, dir + "/./token"},
		{"a missing file with a dot segment", dir + "/missing/token", dir + "/missing/./token"},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			err := withTokenFiles(tt.marked, tt.unmarked).Validate()
			refusal := `providers[1]: provider "idp" sends in tokenFile "` + tt.unmarked + `" the token of provider "k8s", which sets kubernetes`
			if err == nil || !strings.Contains(err.Error(), refusal) {
				t.Errorf("Validate() with the tokenFiles %s and %s error = %v, want one that contains %q", tt.marked, tt.unmarked, err, refusal)
			}
		})
	}
	t.Run("the unmarked provider listed first", func(t *testing.T) {
		cfg := withTokenFiles(token, token)
		cfg.Providers[0], cfg.Providers[1] = cfg.Providers[1], cfg.Providers[0]
		refusal := `providers[0]: provider "idp" sends in tokenFile "` + token + `" the token of provider "k8s", which sets kubernetes`
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), refusal) {
			t.Errorf("Validate() with the unmarked provider first error = %v, want one that contains %q", err, refusal)
		}
	})
	accepted := []struct{ name, marked, unmarked string }{
		{"another file beside it", token, other},
		{"a path that cleans to the token but opens another file", token, dir + "/link-to-child/../token"},
		{"a path that cleans to a missing token but opens a file", dir + "/unmounted", dir + "/link-to-child/../unmounted"},
		{"another missing file beside a missing token", dir + "/missing/token", dir + "/missing/other"},
		{"a missing path that cleans to the token", dir + "/mounted", dir + "/link-to-child/../mounted"},
	}
	for _, tt := range accepted {
		t.Run(tt.name, func(t *testing.T) {
			if err := withTokenFiles(tt.marked, tt.unmarked).Validate(); err != nil {
				t.Errorf("Validate() with the tokenFiles %s and %s error = %v, want none", tt.marked, tt.unmarked, err)
			}
		})
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
		{"no issuer on a marked provider without a tokenFile", map[string]any{"id": "b", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "caFile": "/var/run/ca.crt", "audiences": []string{"netcracker"}, "kubernetes": true}},
		{"no issuer with a tokenFile on an unmarked provider", map[string]any{"id": "b", "jwksUri": "https://idp.example/realms/b/certs", "tokenFile": "/var/run/token"}},
		{"jwksUri without issuer", map[string]any{"id": "b", "jwksUri": "https://idp.example/realms/b/certs"}},
		{"duplicate issuer", map[string]any{"id": "b", "issuer": "https://idp.example/realms/a"}},
		{"tokenFile without jwksUri", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "tokenFile": "/var/run/token"}},
		{"tokenFile without jwksUri on another host, with a CA", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "caFile": "/var/run/ca.crt", "tokenFile": "/var/run/token"}},
		{"issuer on a marked provider", map[string]any{"id": "b", "issuer": "https://kubernetes.default.svc", "caFile": "/var/run/ca.crt", "tokenFile": "/var/run/token", "audiences": []string{"netcracker"}, "kubernetes": true}},
		{"unmarked provider named kubernetes", map[string]any{"id": "kubernetes", "issuer": "https://idp.example/realms/b"}},
		{"unmarked provider named kubernetes in capitals", map[string]any{"id": "Kubernetes", "issuer": "https://idp.example/realms/b"}},
		{"unmarked issuer on an in-cluster name", map[string]any{"id": "b", "issuer": "https://kubernetes.default.svc"}},
		{"unmarked issuer on an in-cluster name with a trailing dot", map[string]any{"id": "b", "issuer": "https://kubernetes.default.svc.cluster.local."}},
		{"unmarked jwksUri on an in-cluster name", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks"}},
		{"unmarked jwksUri on the full in-cluster name, in capitals, with a port", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "jwksUri": "https://KUBERNETES.default.svc.cluster.local:443/openid/v1/jwks"}},
		{"allowMissingAud without audiences", map[string]any{"id": "b", "issuer": "https://idp.example/realms/b", "allowMissingAud": true}},
		{"kubernetes without audiences", map[string]any{"id": "b", "tokenFile": "/var/run/token", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "caFile": "/var/run/ca.crt", "kubernetes": true}},
		{"kubernetes with another audience", map[string]any{"id": "b", "tokenFile": "/var/run/token", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "caFile": "/var/run/ca.crt", "kubernetes": true, "audiences": []string{"account"}}},
		{"kubernetes with netcracker and another audience", map[string]any{"id": "b", "tokenFile": "/var/run/token", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "caFile": "/var/run/ca.crt", "kubernetes": true, "audiences": []string{"netcracker", "account"}}},
		{"kubernetes with allowMissingAud", map[string]any{"id": "b", "tokenFile": "/var/run/token", "jwksUri": "https://kubernetes.default.svc/openid/v1/jwks", "caFile": "/var/run/ca.crt", "kubernetes": true, "audiences": []string{"netcracker"}, "allowMissingAud": true}},
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
	got, err := issuerOfTokenFile(path)
	if err != nil {
		t.Fatalf("issuerOfTokenFile() error = %v", err)
	}
	if got != want {
		t.Errorf("issuerOfTokenFile() = %q, want %q", got, want)
	}
}

func TestIssuerOfTokenFile_RefusesAFileWithoutAnIssuer(t *testing.T) {
	tests := []struct {
		name, path string
	}{
		{"empty file", writeFile(t, "token", "\n")},
		{"two parts", writeFile(t, "token", strings.TrimSuffix(jwtWith(`{"iss": "https://a.example"}`), ".c2ln"))},
		{"four parts", writeFile(t, "token", jwtWith(`{"iss": "https://a.example"}`)+".c2ln")},
		// The payload ends in an asterisk, and the characters before it decode
		// to a JSON object with an iss, so only the check of the decoding
		// refuses it.
		{"payload that is not base64url", writeFile(t, "token", strings.Replace(jwtWith(`{"iss":"https://a.example"}`), ".c2ln", "*.c2ln", 1))},
		{"payload without iss", writeFile(t, "token", jwtWith(`{"sub": "a"}`))},
		{"ISS in place of iss", writeFile(t, "token", jwtWith(`{"ISS": "https://a.example"}`))},
		{"iss that is a number", writeFile(t, "token", jwtWith(`{"iss": 5}`))},
		{"empty iss", writeFile(t, "token", jwtWith(`{"iss": ""}`))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := issuerOfTokenFile(tt.path)
			if err == nil {
				t.Errorf("issuerOfTokenFile(%s) = %q, want an error", tt.path, got)
			}
		})
	}
}

// The error keeps the cause, so the operator reads that the file is missing
// rather than that it holds no JWT.
func TestIssuerOfTokenFile_ReportsAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	if got, err := issuerOfTokenFile(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("issuerOfTokenFile(%s) = %q, %v, want an error that wraps fs.ErrNotExist", path, got, err)
	}
}

func TestIssuerOfTokenFile_ReportsAPayloadThatIsNotJSON(t *testing.T) {
	path := writeFile(t, "token", jwtWith("not json"))
	if got, err := issuerOfTokenFile(path); !errors.As(err, new(*json.SyntaxError)) {
		t.Errorf("issuerOfTokenFile(%s) = %q, %v, want an error that wraps a *json.SyntaxError", path, got, err)
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
