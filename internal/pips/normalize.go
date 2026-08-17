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

package pips

import (
	"encoding/json"
	"fmt"
	"strings"
)

func Normalize(input []byte) (*PIPDocument, *UploadSummary, error) {
	items, err := Parse(input)
	if err != nil {
		return nil, nil, err
	}

	if err := Validate(items); err != nil {
		return nil, nil, err
	}

	return NormalizeItems(items)
}

func NormalizeItems(items []SimplifiedPIP) (*PIPDocument, *UploadSummary, error) {
	normalized := NormalizedPIPs{
		ByName:   make(map[string]NormalizedEntry, len(items)),
		AliasSet: make(map[string]bool, len(items)),
		Local: LocalPIPs{
			Token:  make(map[string]TokenPIPConfig),
			Header: make(map[string]HeaderPIPConfig),
		},
		Remote: RemotePIPs{
			General: make(map[string]GeneralPIPConfig),
		},
		Activation: ActivationIndexes{
			GeneralByResourceTypeOperation: make(map[string]map[string][]string),
		},
	}

	summary := &UploadSummary{Total: len(items)}

	for _, item := range items {
		pipType := resolvePipType(item)
		alias := item.Name[len("subject."):]

		normalized.ByName[item.Name] = NormalizedEntry{
			Name:    item.Name,
			Alias:   alias,
			PipType: pipType,
		}
		normalized.AliasSet[alias] = true

		switch pipType {
		case PipTypeToken:
			normalized.Local.Token[item.Name] = TokenPIPConfig{
				Name:         item.Name,
				Alias:        alias,
				Claim:        strings.TrimSpace(item.Claim),
				DefaultValue: item.DefaultValue,
			}
			summary.Token++

		case PipTypeHeader:
			normalized.Local.Header[item.Name] = HeaderPIPConfig{
				Name:         item.Name,
				Alias:        alias,
				Header:       strings.TrimSpace(item.Header),
				DefaultValue: item.DefaultValue,
			}
			summary.Header++

		case PipTypeGeneral:
			method := strings.ToUpper(strings.TrimSpace(item.HTTPMethod))
			if method == "" {
				// ADR-0066: default method flips GET→POST to match legacy
				// access-control parity (SpringPolicyInformationPointClient:78).
				method = "POST"
			}

			// O-6: lower the polymorphic headers into forward-names + set-pairs.
			forward, set, _ := parseHeaders(item.Headers)

			normalized.Remote.General[item.Name] = GeneralPIPConfig{
				Name:           item.Name,
				Alias:          alias,
				URL:            strings.TrimSpace(item.URL),
				HTTPMethod:     method,
				Query:          item.Query,
				ForwardHeaders: forward,
				SetHeaders:     set,
				Body:           buildGeneralBody(item, method),
				TimeoutSeconds: clampTimeoutSeconds(item.TimeoutSeconds),
				Response:       buildResponseConfig(item),
				DefaultValue:   item.DefaultValue,
			}
			summary.General++
		}
	}

	doc := &PIPDocument{
		Raw: RawPIPDocument{
			Version: 1,
			Items:   items,
		},
		Normalized: normalized,
	}

	return doc, summary, nil
}

// buildGeneralBody chooses the outgoing body for a GENERAL PIP (ADR-0066):
//   - an explicit `body` wins and is used free-form (no wrapper, no auto-id);
//   - otherwise, for POST, the verified legacy wrapper
//     `{id:"${subject.id}", filters:null, requestAttributes:<attrs|null>}` is built;
//   - GET carries no body (legacy sends a body only on POST).
func buildGeneralBody(item SimplifiedPIP, method string) json.RawMessage {
	// A body is only ever sent on POST (GET + body is rejected at validate time;
	// the method guard is defense-in-depth for any caller that bypasses Validate).
	if method != "POST" {
		return nil
	}
	if len(item.Body) > 0 {
		return item.Body
	}
	body, err := buildLegacyWrapperBody(item.RequestAttributes)
	if err != nil {
		return nil
	}
	return body
}

// buildResponseConfig lowers the effective response spec (ADR-0066/0068):
// `response` wins when present; otherwise legacy `jsonPath` (only meaningful when
// pipType is set) lowers to `response.extract` (string form). Legacy `type` is
// dropped — it is accepted at upload but ignored at runtime (body always JSON).
func buildResponseConfig(item SimplifiedPIP) *ResponseConfig {
	if item.Response != nil {
		r := item.Response
		extract := r.Extract
		if isAbsentRaw(extract) {
			extract = nil // JSON null / absent → no extraction, don't carry `null` to Rego
		}
		if len(extract) == 0 && r.Coerce == "" && r.OnMissing == "" {
			return nil
		}
		return &ResponseConfig{
			Extract:   extract,
			Coerce:    r.Coerce,
			OnMissing: r.OnMissing,
		}
	}

	if strings.TrimSpace(item.PipType) != "" {
		jsonPath := strings.TrimSpace(item.JsonPath)
		if jsonPath != "" {
			extract, err := json.Marshal(jsonPath)
			if err != nil {
				return nil
			}
			return &ResponseConfig{Extract: extract}
		}
	}
	return nil
}

func MarshalDocument(doc *PIPDocument) ([]byte, error) {
	content, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PIP document: %w", err)
	}
	return append(content, '\n'), nil
}
