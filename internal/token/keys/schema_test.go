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
	"encoding/json"
	"maps"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The tests of this file compare the checks of ReadDir and Config.Validate
// with the JSON Schema of a provider file, which ADR-0104 R6 makes the format
// of the file. A failure means that the schema and the checks describe two
// formats, or that the schema changed and formatSchema was not updated after
// the change was compared with the checks.

// schemaPath is the JSON Schema of a provider file, relative to this package.
const schemaPath = "../../../api/provider-file.v1.schema.json"

// readSchema returns the JSON Schema of a provider file.
func readSchema(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("%s: %v", schemaPath, err)
	}
	return schema
}

// at returns the value at path in v, a JSON value of the schema, and fails the
// test when a name of path is missing.
func at(t *testing.T, v any, path ...string) any {
	t.Helper()
	for i, name := range path {
		object, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("schema: %s is not an object", strings.Join(path[:i], "."))
		}
		if v, ok = object[name]; !ok {
			t.Fatalf("schema: %s is missing", strings.Join(path[:i+1], "."))
		}
	}
	return v
}

// deref returns the member of $defs that v refers to, where v holds "$ref"
// and at most a "description" beside it. It fails the test on any other
// keyword beside "$ref" and on a target that refers further, since the tests
// that read a provider definition through it evaluate neither.
func deref(t *testing.T, schema map[string]any, v any) map[string]any {
	t.Helper()
	object, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("schema: subschema %v is not an object", v)
	}
	for keyword := range object {
		if keyword != "$ref" && keyword != "description" {
			t.Fatalf("schema: %v holds %q beside $ref, which this test does not evaluate", v, keyword)
		}
	}
	target := def(t, schema, object["$ref"])
	if _, ok := target["$ref"]; ok {
		t.Fatalf("schema: $ref %v names a subschema that holds another $ref, which this test does not follow", object["$ref"])
	}
	return target
}

// def returns the member of $defs that ref, the value of a "$ref", names.
func def(t *testing.T, schema map[string]any, ref any) map[string]any {
	t.Helper()
	s, _ := ref.(string)
	name, ok := strings.CutPrefix(s, "#/$defs/")
	if !ok {
		t.Fatalf("schema: $ref %v is not a member of $defs", ref)
	}
	target, ok := at(t, schema, "$defs", name).(map[string]any)
	if !ok {
		t.Fatalf("schema: $defs/%s is not an object", name)
	}
	return target
}

// names returns the names of the members of object, sorted.
func names(object any) []string {
	m, _ := object.(map[string]any)
	return slices.Sorted(func(yield func(string) bool) {
		for name := range m {
			if !yield(name) {
				return
			}
		}
	})
}

// strs returns the strings of a JSON array of the schema.
func strs(t *testing.T, v any) []string {
	t.Helper()
	items, ok := v.([]any)
	if !ok {
		t.Fatalf("schema: %v is not an array", v)
	}
	out := make([]string, len(items))
	for i, item := range items {
		if out[i], ok = item.(string); !ok {
			t.Fatalf("schema: %v holds %v, which is not a string", v, item)
		}
	}
	return out
}

// branches returns the subschemas that def, the definition of the provider
// under key, adds through allOf for the type typ: the then of each if that
// sets type to typ. It fails the test on a member of allOf that is not one if
// and one then, on an if that tests anything but the type, and on a then that
// holds anything but required and properties, since schemaMembers evaluates
// nothing else.
func branches(t *testing.T, key string, def map[string]any, typ ProviderType) []map[string]any {
	t.Helper()
	all, _ := def["allOf"].([]any)
	var out []map[string]any
	for _, branch := range all {
		if got := names(branch); !reflect.DeepEqual(got, []string{"if", "then"}) {
			t.Fatalf("schema: a member of allOf of the provider %q holds %q; this test reads one if and one then", key, got)
		}
		cond := at(t, branch, "if")
		branchType := at(t, cond, "properties", "type", "const")
		want := map[string]any{"properties": map[string]any{"type": map[string]any{"const": branchType}}, "required": []any{"type"}}
		if !reflect.DeepEqual(cond, want) {
			t.Fatalf("schema: an if of the provider %q is %v; this test reads only an if that sets the type, %v", key, cond, want)
		}
		then, ok := at(t, branch, "then").(map[string]any)
		if !ok {
			t.Fatalf("schema: a then of the provider %q is not an object", key)
		}
		for keyword := range then {
			if keyword != "required" && keyword != "properties" {
				t.Fatalf("schema: a then of the provider %q holds %q, which this test does not evaluate", key, keyword)
			}
		}
		if branchType == string(typ) {
			out = append(out, then)
		}
	}
	return out
}

// schemaMembers returns, as [members] holds them for key, the members that
// def allows for each type, and whether it requires each, where def is the
// definition of the provider under key. It fails the test on a keyword of def
// that it does not evaluate, and reports a def that allows members it does not
// name.
func schemaMembers(t *testing.T, key string, def map[string]any) map[ProviderType]map[string]bool {
	t.Helper()
	checkProviderKeywords(t, key, def)
	out := make(map[ProviderType]map[string]bool)
	for _, typ := range schemaTypes(t, def) {
		out[ProviderType(typ)] = typeMembers(t, key, def, ProviderType(typ))
	}
	return out
}

// checkProviderKeywords fails the test on a keyword of def, the definition of
// the provider under key, that schemaMembers does not evaluate, and reports an
// additionalProperties other than false.
func checkProviderKeywords(t *testing.T, key string, def map[string]any) {
	t.Helper()
	for keyword, value := range def {
		switch keyword {
		case "description", "properties", "required", "allOf", "additionalProperties":
		case "type":
			if value != "object" {
				t.Fatalf("schema: the provider %q has the type %v, want object", key, value)
			}
		default:
			t.Fatalf("schema: the provider %q uses the keyword %q, which this test does not evaluate", key, keyword)
		}
	}
	if got := def["additionalProperties"]; got != false {
		t.Errorf("schema: additionalProperties of the provider %q = %v, want false, since ReadDir refuses every member that the provider does not allow", key, got)
	}
}

// schemaTypes returns the values that the property type of def allows: its
// const, or else its enum.
func schemaTypes(t *testing.T, def map[string]any) []string {
	t.Helper()
	property := at(t, def, "properties", "type").(map[string]any)
	if typ, ok := property["const"].(string); ok {
		return []string{typ}
	}
	return strs(t, at(t, property, "enum"))
}

// typeMembers returns the members that def, the definition of the provider
// under key, allows for the type typ, and whether it requires each.
func typeMembers(t *testing.T, key string, def map[string]any, typ ProviderType) map[string]bool {
	t.Helper()
	allowed := make(map[string]bool)
	for _, name := range names(at(t, def, "properties")) {
		allowed[name] = false
	}
	for _, name := range strs(t, at(t, def, "required")) {
		allowed[name] = true
	}
	for _, then := range branches(t, key, def, typ) {
		applyThen(t, allowed, then)
	}
	return allowed
}

// applyThen marks in allowed the members that then requires, and removes the
// members that it forbids with false.
func applyThen(t *testing.T, allowed map[string]bool, then map[string]any) {
	t.Helper()
	if required, ok := then["required"]; ok {
		for _, name := range strs(t, required) {
			allowed[name] = true
		}
	}
	properties, _ := then["properties"].(map[string]any)
	for name, sub := range properties {
		if sub == false {
			delete(allowed, name)
		}
	}
}

func TestSchema_HoldsTheMembersOfAFileThatReadDirReads(t *testing.T) {
	schema := readSchema(t)
	if got, want := names(at(t, schema, "properties")), []string{"$schema", "providers"}; !reflect.DeepEqual(got, want) {
		t.Errorf("schema: the members of a provider file are %q, want %q", got, want)
	}
	if got, want := strs(t, at(t, schema, "required")), []string{"providers"}; !reflect.DeepEqual(got, want) {
		t.Errorf("schema: a provider file requires %q, want %q", got, want)
	}
	if got := at(t, schema, "additionalProperties"); got != false {
		t.Errorf("schema: additionalProperties of a provider file = %v, want false", got)
	}
}

func TestSchema_AllowsTheKeysTypesAndMembersThatReadDirAllows(t *testing.T) {
	schema := readSchema(t)
	providers := at(t, schema, "properties", "providers")
	if got, want := names(at(t, providers, "properties")), slices.Sorted(func(yield func(string) bool) {
		for key := range members {
			if !yield(key) {
				return
			}
		}
	}); !reflect.DeepEqual(got, want) {
		t.Errorf("schema: the keys of providers are %q, and ReadDir allows %q", got, want)
	}
	if got := at(t, providers, "additionalProperties"); got != false {
		t.Errorf("schema: additionalProperties of providers = %v, want false", got)
	}
	for key, want := range members {
		def := deref(t, schema, at(t, providers, "properties", key))
		if got := schemaMembers(t, key, def); !reflect.DeepEqual(got, want) {
			t.Errorf("schema: the provider %q allows and requires the members %v by type, and ReadDir %v", key, got, want)
		}
	}
}

// formatSchema is the schema of a provider file without its description
// annotations: the format that the tests of this file compare with ReadDir and
// Validate. A change of the schema fails
// TestSchema_IsTheFormatThatTheseTestsCompare until someone has compared the
// change with the checks in Go and updated this literal, which is the output of
//
//	grep -v '^ *"description":' api/provider-file.v1.schema.json
const formatSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://raw.githubusercontent.com/Netcracker/qubership-authz-agent/main/api/provider-file.v1.schema.json",
  "title": "Provider file",
  "type": "object",
  "properties": {
    "$schema": {
      "type": "string"
    },
    "providers": {
      "type": "object",
      "properties": {
        "identity-provider": {
          "$ref": "#/$defs/identityProvider"
        },
        "kubernetes": {
          "$ref": "#/$defs/kubernetes"
        }
      },
      "additionalProperties": false
    }
  },
  "required": [
    "providers"
  ],
  "additionalProperties": false,
  "$defs": {
    "identityProvider": {
      "type": "object",
      "properties": {
        "type": {
          "enum": [
            "realms",
            "single"
          ]
        },
        "issuer": {
          "$ref": "#/$defs/issuer"
        },
        "issuerTemplate": {
          "$ref": "#/$defs/realmTemplateUrl"
        },
        "jwksUri": {
          "$ref": "#/$defs/jwksUri"
        },
        "readinessRealms": {
          "type": "array",
          "items": {
            "type": "string",
            "minLength": 1
          }
        },
        "audience": {
          "$ref": "#/$defs/audience"
        }
      },
      "required": [
        "type",
        "jwksUri",
        "audience"
      ],
      "additionalProperties": false,
      "allOf": [
        {
          "if": {
            "properties": {
              "type": {
                "const": "realms"
              }
            },
            "required": [
              "type"
            ]
          },
          "then": {
            "required": [
              "issuerTemplate"
            ],
            "properties": {
              "issuer": false,
              "jwksUri": {
                "$ref": "#/$defs/realmTemplateUrl"
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "type": {
                "const": "single"
              }
            },
            "required": [
              "type"
            ]
          },
          "then": {
            "required": [
              "issuer"
            ],
            "properties": {
              "issuerTemplate": false,
              "readinessRealms": false,
              "jwksUri": {
                "$ref": "#/$defs/url"
              }
            }
          }
        }
      ]
    },
    "kubernetes": {
      "type": "object",
      "properties": {
        "type": {
          "const": "single"
        },
        "issuer": {
          "$ref": "#/$defs/issuer"
        },
        "jwksUri": {
          "allOf": [
            {
              "$ref": "#/$defs/url"
            },
            {
              "pattern": "^[Hh][Tt][Tt][Pp][Ss]://"
            }
          ]
        },
        "jwksBearerTokenFile": {
          "type": "string",
          "pattern": "^/"
        },
        "audience": {
          "$ref": "#/$defs/audience",
          "properties": {
            "mode": {
              "const": "matchAny"
            }
          }
        }
      },
      "required": [
        "type",
        "issuer",
        "jwksUri",
        "audience"
      ],
      "additionalProperties": false
    },
    "issuer": {
      "$ref": "#/$defs/url"
    },
    "audience": {
      "type": "object",
      "properties": {
        "mode": {
          "enum": [
            "matchAny",
            "ignore"
          ]
        },
        "values": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "string",
            "minLength": 1
          }
        }
      },
      "required": [
        "mode"
      ],
      "additionalProperties": false,
      "if": {
        "properties": {
          "mode": {
            "const": "matchAny"
          }
        },
        "required": [
          "mode"
        ]
      },
      "then": {
        "required": [
          "values"
        ]
      },
      "else": {
        "properties": {
          "values": false
        }
      }
    },
    "jwksUri": {
      "type": "string",
      "pattern": "^[Hh][Tt][Tt][Pp][Ss]?://"
    },
    "url": {
      "type": "string",
      "pattern": "^[A-Za-z][A-Za-z0-9+.-]*://[^/?#{}]+([/?][^#{}]*)?$",
      "not": {
        "pattern": "[^\\x21-\\x7e]"
      }
    },
    "realmTemplateUrl": {
      "type": "string",
      "pattern": "^[A-Za-z][A-Za-z0-9+.-]*://[^/?#{}]+(/[^/?#{}]*)*/\\{realm\\}(/[^/?#{}]*)*(\\?[^#{}]*)?$",
      "not": {
        "pattern": "[^\\x21-\\x7e]"
      }
    }
  }
}
`

// withoutDescriptions returns a copy of v, a schema or a part of one, without
// the annotation description. The members of a properties or $defs object are
// names rather than keywords, so a member named description stays.
func withoutDescriptions(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for keyword, value := range v {
			switch keyword {
			case "description":
			case "properties", "$defs":
				out[keyword] = namedWithoutDescriptions(value)
			default:
				out[keyword] = withoutDescriptions(value)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = withoutDescriptions(item)
		}
		return out
	}
	return v
}

// namedWithoutDescriptions applies withoutDescriptions to each member of
// value, an object whose members are names, and keeps every name. A value
// that is not an object goes to withoutDescriptions whole.
func namedWithoutDescriptions(value any) any {
	named, ok := value.(map[string]any)
	if !ok {
		return withoutDescriptions(value)
	}
	kept := make(map[string]any, len(named))
	for name, sub := range named {
		kept[name] = withoutDescriptions(sub)
	}
	return kept
}

// differences returns the JSON paths, below path, at which got and want
// differ, sorted.
func differences(path string, got, want any) []string {
	gotObject, gotIsObject := got.(map[string]any)
	wantObject, wantIsObject := want.(map[string]any)
	if gotIsObject && wantIsObject {
		var out []string
		for name, gotValue := range gotObject {
			wantValue, ok := wantObject[name]
			if !ok {
				out = append(out, path+"/"+name)
				continue
			}
			out = append(out, differences(path+"/"+name, gotValue, wantValue)...)
		}
		for name := range maps.Keys(wantObject) {
			if _, ok := gotObject[name]; !ok {
				out = append(out, path+"/"+name)
			}
		}
		slices.Sort(out)
		return out
	}
	if !reflect.DeepEqual(got, want) {
		return []string{path}
	}
	return nil
}

func TestWithoutDescriptions_KeepsAMemberNamedDescription(t *testing.T) {
	var schema, want any
	if err := json.Unmarshal([]byte(`{"description": "a", "properties": {"description": {"type": "string", "description": "b"}}, "$defs": {"description": {"description": "c"}}}`), &schema); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"properties": {"description": {"type": "string"}}, "$defs": {"description": {}}}`), &want); err != nil {
		t.Fatal(err)
	}
	if got := withoutDescriptions(schema); !reflect.DeepEqual(got, want) {
		t.Errorf("withoutDescriptions(%v) = %v, want %v", schema, got, want)
	}
}

// A keyword whose value is null is a change of the schema like any other.
func TestDifferences_NamesAKeywordThatOnlyOneSideHolds(t *testing.T) {
	var got, want any
	if err := json.Unmarshal([]byte(`{"a": {"$ref": "#/x", "const": null}, "b": 1}`), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"a": {"$ref": "#/x"}, "c": 2}`), &want); err != nil {
		t.Fatal(err)
	}
	if paths, wantPaths := differences("", got, want), []string{"/a/const", "/b", "/c"}; !reflect.DeepEqual(paths, wantPaths) {
		t.Errorf("differences(%v, %v) = %q, want %q", got, want, paths, wantPaths)
	}
}

func TestSchema_IsTheFormatThatTheseTestsCompare(t *testing.T) {
	var want any
	if err := json.Unmarshal([]byte(formatSchema), &want); err != nil {
		t.Fatal(err)
	}
	got := withoutDescriptions(readSchema(t))
	if paths := differences("", got, want); len(paths) > 0 {
		t.Errorf("schema: %s differs from formatSchema at %q; compare the change with ReadDir and Config.Validate, extend the tests of this file that compare them, then update formatSchema", schemaPath, paths)
	}
}

func TestSchema_NamesTheAudienceModesThatValidateAccepts(t *testing.T) {
	schema := readSchema(t)
	audiences := map[string]Audience{
		string(MatchAny): {Mode: MatchAny, Values: []string{"netcracker"}},
		string(Ignore):   {Mode: Ignore},
	}
	modes := strs(t, at(t, schema, "$defs", "audience", "properties", "mode", "enum"))
	if got, want := slices.Sorted(slices.Values(modes)), slices.Sorted(maps.Keys(audiences)); !reflect.DeepEqual(got, want) {
		t.Fatalf("schema: the audience modes are %q, and this test builds audiences of the modes %q", got, want)
	}
	for _, mode := range modes {
		p := Provider{ID: IdentityProviderID, Type: Single, Issuer: "https://kc/a", JWKSURI: "https://kc/certs", Audience: audiences[mode]}
		if err := (Config{Providers: []Provider{p}}).Validate(); err != nil {
			t.Errorf("Validate() with the audience mode %q of the schema error = %v, want none", mode, err)
		}
	}
}

// accepts reports whether the string s is valid under the subschema v. It
// evaluates the keywords the schema applies to the address members and fails
// the test on any other keyword, which it would otherwise ignore.
func accepts(t *testing.T, schema map[string]any, v any, s string) bool {
	t.Helper()
	object, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("schema: subschema %v is not an object", v)
	}
	for keyword, value := range object {
		if !keywordAccepts(t, schema, keyword, value, s) {
			return false
		}
	}
	return true
}

// keywordAccepts reports whether s is valid under the keyword of a subschema
// with value, and fails the test on a keyword that accepts does not evaluate.
func keywordAccepts(t *testing.T, schema map[string]any, keyword string, value any, s string) bool {
	t.Helper()
	switch keyword {
	case "description":
		return true
	case "type":
		if value != "string" {
			t.Fatalf("schema: an address member has the type %v, want string", value)
		}
		return true
	case "$ref":
		return accepts(t, schema, def(t, schema, value), s)
	case "pattern":
		// Go's regexp reads the patterns of the schema as ECMA-262 does, as
		// ADR-0104 states.
		return regexp.MustCompile(value.(string)).MatchString(s)
	case "not":
		return !accepts(t, schema, value, s)
	case "allOf":
		for _, sub := range value.([]any) {
			if !accepts(t, schema, sub, s) {
				return false
			}
		}
		return true
	}
	t.Fatalf("schema: an address member uses the keyword %q, which this test does not evaluate", keyword)
	return false
}

// memberValid reports whether value is valid under every subschema that def,
// the definition of the provider under key, applies to its member name for
// the type typ: the property and the property of each then of that type.
func memberValid(t *testing.T, schema map[string]any, key string, def map[string]any, typ ProviderType, name, value string) bool {
	t.Helper()
	schemas := []any{at(t, def, "properties", name)}
	for _, then := range branches(t, key, def, typ) {
		if sub, ok := at(t, then, "properties").(map[string]any)[name]; ok {
			schemas = append(schemas, sub)
		}
	}
	for _, sub := range schemas {
		if !accepts(t, schema, sub, value) {
			return false
		}
	}
	return true
}

// The schema accepts some addresses that net/url cannot parse or reads with no
// host name, and the agent refuses them. The agent accepts no address of the
// provider identity-provider that the schema refuses.
func TestSchema_AcceptsTheAddressesThatValidateAccepts(t *testing.T) {
	schema := readSchema(t)
	idp := deref(t, schema, at(t, schema, "properties", "providers", "properties", IdentityProviderID))
	type member struct {
		typ      ProviderType
		name     string
		provider func(value string) Provider
	}
	issuer := member{Single, "issuer", func(v string) Provider {
		return Provider{ID: IdentityProviderID, Type: Single, Issuer: v, JWKSURI: "https://kc/certs", Audience: ignoreAudience}
	}}
	issuerTemplate := member{Realms, "issuerTemplate", func(v string) Provider {
		return Provider{ID: IdentityProviderID, Type: Realms, IssuerTemplate: v, JWKSURI: "https://kc/{realm}/certs", Audience: ignoreAudience}
	}}
	singleJWKS := member{Single, "jwksUri", func(v string) Provider {
		return Provider{ID: IdentityProviderID, Type: Single, Issuer: "https://kc/a", JWKSURI: v, Audience: ignoreAudience}
	}}
	realmsJWKS := member{Realms, "jwksUri", func(v string) Provider {
		return Provider{ID: IdentityProviderID, Type: Realms, IssuerTemplate: "https://kc/{realm}", JWKSURI: v, Audience: ignoreAudience}
	}}
	tests := []struct {
		name          string
		member        member
		value         string
		schema, agent bool
	}{
		{"issuer", issuer, "https://kc.example/auth/realms/a", true, true},
		{"issuer with the scheme in upper case", issuer, "HTTPS://kc/a", true, true},
		{"issuer with another scheme", issuer, "x-1.a+b://kc/realms", true, true},
		{"issuer with a query", issuer, "https://kc/a?x=1", true, true},
		{"issuer with a query and no path", issuer, "https://kc?x", true, true},
		{"issuer with ! and ~", issuer, "https://kc/!a~", true, true},
		{"empty issuer", issuer, "", false, false},
		{"issuer without a scheme", issuer, "kc/a", false, false},
		{"issuer that is a path", issuer, "/auth/realms/a", false, false},
		{"issuer with nothing before ://", issuer, "://kc", false, false},
		{"issuer whose scheme starts with a digit", issuer, "1http://kc", false, false},
		{"issuer without a host", issuer, "https:///a", false, false},
		{"issuer with a space", issuer, "https://kc/a b", false, false},
		{"issuer with a letter outside ASCII", issuer, "https://kc/ä", false, false},
		{"issuer with DEL", issuer, "https://kc/\x7f", false, false},
		{"issuer with a fragment", issuer, "https://kc/a#b", false, false},
		{"issuer with an empty fragment", issuer, "https://kc/a#", false, false},
		{"issuer with braces", issuer, "https://kc/{x}", false, false},
		{"issuer with {realm}", issuer, "https://kc/{realm}", false, false},
		{"issuer with a port that net/url cannot parse", issuer, "https://kc:x/a", true, false},
		{"issuer with a user and no host, which net/url reads as no host", issuer, "https://user@/a", true, false},
		{"issuer with a broken escape in the host, which net/url cannot parse", issuer, "http://kc%zz/a", true, false},
		{"issuer with a port and no host, which net/url reads as no host name", issuer, "http://:8080/a", true, false},
		{"issuer with an IPv6 host and a port", issuer, "http://[::1]:8080/a", true, true},
		{"issuer with a user and a host", issuer, "http://user@kc/a", true, true},
		{"issuer with a user, a port, and no host, which net/url reads as no host name", issuer, "https://user@:8080/a", true, false},
		{"issuerTemplate", issuerTemplate, "http://kc/auth/realms/{realm}", true, true},
		{"issuerTemplate with a segment after {realm}", issuerTemplate, "http://kc/realms/{realm}/issuer", true, true},
		{"issuerTemplate with a query", issuerTemplate, "http://kc/realms/{realm}?v=1", true, true},
		{"issuerTemplate with {realm} as the only segment", issuerTemplate, "http://kc/{realm}", true, true},
		{"issuerTemplate without {realm}", issuerTemplate, "http://kc/auth/realms/a", false, false},
		{"issuerTemplate with {realm} twice", issuerTemplate, "http://kc/{realm}/{realm}", false, false},
		{"issuerTemplate with {realm} in the host", issuerTemplate, "http://{realm}.kc/a", false, false},
		{"issuerTemplate with {realm} in part of a segment", issuerTemplate, "http://kc/t-{realm}", false, false},
		{"issuerTemplate with {realm} before more text", issuerTemplate, "http://kc/{realm}x", false, false},
		{"issuerTemplate with {realm} in the query", issuerTemplate, "http://kc/auth?/{realm}", false, false},
		{"issuerTemplate with a fragment", issuerTemplate, "http://kc/auth/realms/{realm}#", false, false},
		{"issuerTemplate without a host", issuerTemplate, "http:///{realm}", false, false},
		{"issuerTemplate with a broken escape in the host, which net/url cannot parse", issuerTemplate, "http://kc%zz/{realm}", true, false},
		{"jwksUri", singleJWKS, "https://kc/certs", true, true},
		{"jwksUri over http in upper case", singleJWKS, "HTTP://kc/certs", true, true},
		{"jwksUri over https in mixed case", singleJWKS, "Https://kc/certs", true, true},
		{"jwksUri over ftp", singleJWKS, "ftp://kc/certs", false, false},
		{"jwksUri of a file", singleJWKS, "file:///etc/jwks.json", false, false},
		{"jwksUri with a scheme that starts with http", singleJWKS, "httpx://kc/certs", false, false},
		{"jwksUri with braces", singleJWKS, "https://kc/certs{x}", false, false},
		{"jwksUri with a port that net/url cannot parse", singleJWKS, "https://kc:x/certs", true, false},
		{"realms jwksUri", realmsJWKS, "http://kc/auth/realms/{realm}/protocol/openid-connect/certs", true, true},
		{"realms jwksUri without {realm}", realmsJWKS, "http://kc/certs", false, false},
		{"realms jwksUri over ftp", realmsJWKS, "ftp://kc/{realm}", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := memberValid(t, schema, IdentityProviderID, idp, tt.member.typ, tt.member.name, tt.value)
			if valid != tt.schema {
				t.Errorf("schema: %s %q of a %s provider valid = %t, want %t", tt.member.name, tt.value, tt.member.typ, valid, tt.schema)
			}
			err := Config{Providers: []Provider{tt.member.provider(tt.value)}}.Validate()
			if (err == nil) != tt.agent {
				t.Errorf("Validate() with the %s %q of a %s provider error = %v, want accepted %t", tt.member.name, tt.value, tt.member.typ, err, tt.agent)
			}
		})
	}
}
