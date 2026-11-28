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
	"path/filepath"
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

// typeSchemas returns, for each type that def, the definition of the provider
// under key, allows, the subschema that holds the members of a provider of
// that type. A definition without allOf holds them itself and allows the one
// type that the const of its property type names. A definition with allOf
// allows the types of an enum, holds no member but type, and refers, in the
// then of one if for each type, to the subschema of that type. typeSchemas
// fails the test on any other shape, since the tests that read the members
// through it evaluate nothing else.
func typeSchemas(t *testing.T, schema map[string]any, key string, def map[string]any) map[ProviderType]map[string]any {
	t.Helper()
	all, ok := def["allOf"].([]any)
	if !ok {
		typ, _ := at(t, def, "properties", "type", "const").(string)
		return map[ProviderType]map[string]any{ProviderType(typ): def}
	}
	checkKeywords(t, key, def, "allOf")
	if got := names(at(t, def, "properties")); !reflect.DeepEqual(got, []string{"type"}) {
		t.Fatalf("schema: the provider %q with allOf holds the members %q itself; this test reads only type there", key, got)
	}
	if got := strs(t, at(t, def, "required")); !reflect.DeepEqual(got, []string{"type"}) {
		t.Fatalf("schema: the provider %q with allOf requires %q itself; this test reads only type there", key, got)
	}
	out := make(map[ProviderType]map[string]any)
	for _, branch := range all {
		if got := names(branch); !reflect.DeepEqual(got, []string{"if", "then"}) {
			t.Fatalf("schema: a member of allOf of the provider %q holds %q; this test reads one if and one then", key, got)
		}
		cond := at(t, branch, "if")
		branchType, _ := at(t, cond, "properties", "type", "const").(string)
		want := map[string]any{"properties": map[string]any{"type": map[string]any{"const": branchType}}, "required": []any{"type"}}
		if !reflect.DeepEqual(cond, want) {
			t.Fatalf("schema: an if of the provider %q is %v; this test reads only an if that sets the type, %v", key, cond, want)
		}
		sub := deref(t, schema, at(t, branch, "then"))
		if got := at(t, sub, "properties", "type", "const"); got != branchType {
			t.Fatalf("schema: the then of the type %q of the provider %q refers to a subschema of the type %v", branchType, key, got)
		}
		out[ProviderType(branchType)] = sub
	}
	var got []string
	for typ := range out {
		got = append(got, string(typ))
	}
	slices.Sort(got)
	if want := slices.Sorted(slices.Values(strs(t, at(t, def, "properties", "type", "enum")))); !reflect.DeepEqual(got, want) {
		t.Fatalf("schema: the provider %q has the types %q and a then for the types %q", key, want, got)
	}
	return out
}

// checkKeywords fails the test on a keyword of def, the definition of the
// provider under key or a subschema of it, that is neither one that every such
// subschema may hold nor one of extra, and on a type other than object.
func checkKeywords(t *testing.T, key string, def map[string]any, extra ...string) {
	t.Helper()
	for keyword, value := range def {
		switch {
		case keyword == "type" && value != "object":
			t.Fatalf("schema: a subschema of the provider %q has the type %v, want object", key, value)
		case slices.Contains([]string{"description", "type", "properties", "required"}, keyword), slices.Contains(extra, keyword):
		default:
			t.Fatalf("schema: a subschema of the provider %q uses the keyword %q, which this test does not evaluate", key, keyword)
		}
	}
}

// schemaMembers returns, as [members] holds them for key, the members that
// def, the definition of the provider under key, allows for each type, and
// whether it requires each. It fails the test on a keyword that it does not
// evaluate, and reports a subschema that allows members it does not name.
func schemaMembers(t *testing.T, schema map[string]any, key string, def map[string]any) map[ProviderType]map[string]bool {
	t.Helper()
	out := make(map[ProviderType]map[string]bool)
	for typ, sub := range typeSchemas(t, schema, key, def) {
		checkKeywords(t, key, sub, "additionalProperties")
		if got := sub["additionalProperties"]; got != false {
			t.Errorf("schema: additionalProperties of the provider %q of the type %q = %v, want false, since ReadDir refuses every member that the provider does not allow", key, typ, got)
		}
		allowed := make(map[string]bool)
		for _, name := range names(at(t, sub, "properties")) {
			allowed[name] = false
		}
		for _, name := range strs(t, at(t, sub, "required")) {
			allowed[name] = true
		}
		out[typ] = allowed
	}
	return out
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
		if got := schemaMembers(t, schema, key, def); !reflect.DeepEqual(got, want) {
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
        }
      },
      "required": [
        "type"
      ],
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
            "$ref": "#/$defs/identityProviderRealms"
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
            "$ref": "#/$defs/identityProviderSingle"
          }
        }
      ]
    },
    "identityProviderRealms": {
      "type": "object",
      "properties": {
        "type": {
          "const": "realms"
        },
        "issuerTemplate": {
          "$ref": "#/$defs/realmTemplateUrl"
        },
        "jwksUri": {
          "allOf": [
            {
              "$ref": "#/$defs/httpUrl"
            },
            {
              "$ref": "#/$defs/realmTemplateUrl"
            }
          ]
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
        "issuerTemplate",
        "jwksUri",
        "audience"
      ],
      "additionalProperties": false
    },
    "identityProviderSingle": {
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
              "$ref": "#/$defs/httpUrl"
            },
            {
              "$ref": "#/$defs/url"
            }
          ]
        },
        "audience": {
          "$ref": "#/$defs/audience"
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
        }
      },
      "required": [
        "type",
        "issuer",
        "jwksUri"
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
      "allOf": [
        {
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
          }
        },
        {
          "if": {
            "properties": {
              "mode": {
                "const": "ignore"
              }
            },
            "required": [
              "mode"
            ]
          },
          "then": {
            "properties": {
              "mode": true
            },
            "additionalProperties": false
          }
        }
      ]
    },
    "httpUrl": {
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

// audienceValid reports whether an audience whose members are present, by
// name, is valid under the members that def, the subschema audience, allows
// and requires, and under the then of each if whose mode it holds. It reads
// only which members are present, and fails the test on a keyword that it
// does not evaluate.
func audienceValid(t *testing.T, def map[string]any, mode string, present []string) bool {
	t.Helper()
	valid := membersValid(t, def, present)
	for _, branch := range at(t, def, "allOf").([]any) {
		cond := at(t, branch, "if")
		want := map[string]any{"properties": map[string]any{"mode": map[string]any{"const": at(t, cond, "properties", "mode", "const")}}, "required": []any{"mode"}}
		if !reflect.DeepEqual(cond, want) {
			t.Fatalf("schema: an if of audience is %v; this test reads only an if that sets the mode, %v", cond, want)
		}
		if at(t, cond, "properties", "mode", "const") == mode {
			valid = valid && membersValid(t, at(t, branch, "then").(map[string]any), present)
		}
	}
	return valid
}

// membersValid reports whether an object whose members are present, by name,
// is valid under the required, properties, and additionalProperties of sub,
// reading of properties only the names. It fails the test on any other keyword
// beside allOf, which audienceValid reads, and the annotations.
func membersValid(t *testing.T, sub map[string]any, present []string) bool {
	t.Helper()
	for keyword := range sub {
		if !slices.Contains([]string{"description", "type", "properties", "required", "additionalProperties", "allOf"}, keyword) {
			t.Fatalf("schema: a subschema of audience uses the keyword %q, which this test does not evaluate", keyword)
		}
	}
	if required, ok := sub["required"]; ok {
		for _, name := range strs(t, required) {
			if !slices.Contains(present, name) {
				return false
			}
		}
	}
	if sub["additionalProperties"] == false {
		properties, _ := sub["properties"].(map[string]any)
		for _, name := range present {
			if _, ok := properties[name]; !ok {
				return false
			}
		}
	}
	return true
}

// Each row holds the mode with values or without them, so the two conditions
// of the schema on the mode meet both.
func TestSchema_DecidesWhetherAnAudienceHoldsValuesAsValidateDoes(t *testing.T) {
	schema := readSchema(t)
	def := at(t, schema, "$defs", "audience").(map[string]any)
	tests := []struct {
		name  string
		mode  AudienceMode
		value bool
		valid bool
	}{
		{"matchAny with values", MatchAny, true, true},
		{"matchAny without values", MatchAny, false, false},
		{"ignore without values", Ignore, false, true},
		{"ignore with values", Ignore, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			present := []string{"mode"}
			audience := Audience{Mode: tt.mode}
			if tt.value {
				present = append(present, "values")
				audience.Values = []string{"netcracker"}
			}
			if got := audienceValid(t, def, string(tt.mode), present); got != tt.valid {
				t.Errorf("schema: an audience with the members %q and the mode %q valid = %t, want %t", present, tt.mode, got, tt.valid)
			}
			p := Provider{ID: IdentityProviderID, Type: Single, Issuer: "https://kc/a", JWKSURI: "https://kc/certs", Audience: audience}
			if err := (Config{Providers: []Provider{p}}).Validate(); (err == nil) != tt.valid {
				t.Errorf("Validate() with the audience %+v error = %v, want accepted %t", audience, err, tt.valid)
			}
		})
	}
}

func TestSchema_HasTheIDThatAnErrorNames(t *testing.T) {
	if got := at(t, readSchema(t), "$id"); got != schemaID {
		t.Errorf("schema: $id = %v, and an error names the schema %s", got, schemaID)
	}
}

// examplesPath holds the example provider files of ADR-0104, relative to this
// package: the schema accepts every file in its directory valid and refuses
// every file in invalid.
const examplesPath = "../../../api/examples/provider-file"

// Each example stands alone in a provider directory, so ReadDir checks it
// apart from the others. A refused example breaks the schema, so its error
// names the schema.
func TestReadDir_AcceptsEveryValidExampleAndRefusesEveryInvalidOne(t *testing.T) {
	for _, set := range []struct {
		dir   string
		valid bool
	}{{"valid", true}, {"invalid", false}} {
		entries, err := os.ReadDir(filepath.Join(examplesPath, set.dir))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) == 0 {
			t.Fatalf("%s holds no example", filepath.Join(examplesPath, set.dir))
		}
		for _, entry := range entries {
			t.Run(set.dir+"/"+entry.Name(), func(t *testing.T) {
				data, err := os.ReadFile(filepath.Join(examplesPath, set.dir, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				dir := providerDir(t, map[string]string{entry.Name(): string(data)})
				_, err = ReadDir(dir)
				switch {
				case set.valid && err != nil:
					t.Errorf("ReadDir() of the valid example %s error = %v, want none", entry.Name(), err)
				case !set.valid && (err == nil || !strings.HasSuffix(err.Error(), " (schema "+schemaID+")")):
					t.Errorf("ReadDir() of the invalid example %s error = %v, want an error that names the schema", entry.Name(), err)
				}
			})
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

// memberValid reports whether value is valid under the subschema that def, the
// definition of the provider under key, applies to its member name for the
// type typ.
func memberValid(t *testing.T, schema map[string]any, key string, def map[string]any, typ ProviderType, name, value string) bool {
	t.Helper()
	return accepts(t, schema, at(t, typeSchemas(t, schema, key, def)[typ], "properties", name), value)
}

// The schema accepts some addresses that net/url cannot parse or reads with no
// host name, and the agent refuses them with an error that names no schema.
// The agent accepts no address that the schema refuses, and its error for such
// an address names the schema.
func TestSchema_AcceptsTheAddressesThatValidateAccepts(t *testing.T) {
	schema := readSchema(t)
	type member struct {
		key      string
		typ      ProviderType
		name     string
		provider func(value string) Provider
	}
	issuer := member{IdentityProviderID, Single, "issuer", func(v string) Provider {
		return Provider{ID: IdentityProviderID, Type: Single, Issuer: v, JWKSURI: "https://kc/certs", Audience: ignoreAudience}
	}}
	issuerTemplate := member{IdentityProviderID, Realms, "issuerTemplate", func(v string) Provider {
		return Provider{ID: IdentityProviderID, Type: Realms, IssuerTemplate: v, JWKSURI: "https://kc/{realm}/certs", Audience: ignoreAudience}
	}}
	singleJWKS := member{IdentityProviderID, Single, "jwksUri", func(v string) Provider {
		return Provider{ID: IdentityProviderID, Type: Single, Issuer: "https://kc/a", JWKSURI: v, Audience: ignoreAudience}
	}}
	realmsJWKS := member{IdentityProviderID, Realms, "jwksUri", func(v string) Provider {
		return Provider{ID: IdentityProviderID, Type: Realms, IssuerTemplate: "https://kc/{realm}", JWKSURI: v, Audience: ignoreAudience}
	}}
	kubernetesIssuer := member{KubernetesID, Single, "issuer", func(v string) Provider {
		return Provider{ID: KubernetesID, Type: Single, Issuer: v, JWKSURI: "https://k8s/jwks"}
	}}
	kubernetesJWKS := member{KubernetesID, Single, "jwksUri", func(v string) Provider {
		return Provider{ID: KubernetesID, Type: Single, Issuer: "https://k8s", JWKSURI: v}
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
		{"issuer of kubernetes", kubernetesIssuer, "https://kubernetes.default.svc.cluster.local", true, true},
		{"issuer of kubernetes with a fragment", kubernetesIssuer, "https://k8s#x", false, false},
		{"jwksUri of kubernetes over https", kubernetesJWKS, "https://kubernetes.default.svc/openid/v1/jwks", true, true},
		{"jwksUri of kubernetes over https in upper case", kubernetesJWKS, "HTTPS://oidc.example/jwks", true, true},
		{"jwksUri of kubernetes over http", kubernetesJWKS, "http://kubernetes.default.svc/openid/v1/jwks", false, false},
		{"jwksUri of kubernetes with a port that net/url cannot parse", kubernetesJWKS, "https://k8s:x/jwks", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def := deref(t, schema, at(t, schema, "properties", "providers", "properties", tt.member.key))
			valid := memberValid(t, schema, tt.member.key, def, tt.member.typ, tt.member.name, tt.value)
			if valid != tt.schema {
				t.Errorf("schema: %s %q of the %s provider %q valid = %t, want %t", tt.member.name, tt.value, tt.member.typ, tt.member.key, valid, tt.schema)
			}
			err := Config{Providers: []Provider{tt.member.provider(tt.value)}}.Validate()
			if (err == nil) != tt.agent {
				t.Errorf("Validate() with the %s %q of the %s provider %q error = %v, want accepted %t", tt.member.name, tt.value, tt.member.typ, tt.member.key, err, tt.agent)
			}
			if named := err != nil && strings.Contains(err.Error(), schemaID); err != nil && named == tt.schema {
				t.Errorf("Validate() with the %s %q of the %s provider %q error = %v, which names the schema %t, want %t", tt.member.name, tt.value, tt.member.typ, tt.member.key, err, named, !tt.schema)
			}
		})
	}
}
