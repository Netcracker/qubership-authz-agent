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

package paritysuite

import (
	"fmt"

	"authz-agent/test/parity/suite/model"
)

// ParityEndpointID enumerates the parity-contract Summary Table rows the Go
// helper layer implements directly. CLANG / AGG / SUB / ENT rows inherit the
// id of the parity-contract row they cite (check/resource → PSUITE_ROW_2,
// check/filter → PSUITE_ROW_6, etc.) — they do not get their own id because
// the row→Go-struct binding is the thing this enum drives.
type ParityEndpointID int

const (
	PSUITE_ROW_1_API_VERSION ParityEndpointID = iota + 1
	PSUITE_ROW_2_CHECK_RESOURCE_V1
	PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1
	PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1
	PSUITE_ROW_5_PREVIEW_BULK_OPERATIONS_V1
	PSUITE_ROW_6_CHECK_FILTER_V1
	PSUITE_ROW_7_CHECK_RESOURCE_V2
	PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2
	PSUITE_ROW_9_PREVIEW_BULK_OPERATIONS_V2
	PSUITE_ROW_10_CHECK_FILTER_V2
)

// RowMeta holds the canonical per-row metadata the GoldenComparator and
// record-mode writer use to pick the right golden-factory and the right
// cmp.Diff options.
type RowMeta struct {
	ID                ParityEndpointID
	Name              string
	HTTPMethod        string
	PathTmpl          string
	GoldenDir         string
	IgnoreObligations bool
	SortSlices        bool
}

// rowMetas is keyed by ParityEndpointID and populated from the parity
// contract's Summary Table. IgnoreObligations flips for v2 rows 7/8/9/10
// per D-E. SortSlices flips for rows 3/4/5/8/9 where the wire order is
// "LinkedHashSet-ordered but the client discards order" — the comparator
// therefore sorts before running cmp.Diff per D-M.
var rowMetas = map[ParityEndpointID]RowMeta{
	PSUITE_ROW_1_API_VERSION: {
		ID: PSUITE_ROW_1_API_VERSION, Name: "api-version", HTTPMethod: "GET",
		PathTmpl: "/api-version", GoldenDir: "api-version",
	},
	PSUITE_ROW_2_CHECK_RESOURCE_V1: {
		ID: PSUITE_ROW_2_CHECK_RESOURCE_V1, Name: "check-resource-v1", HTTPMethod: "POST",
		PathTmpl: "/access/v1/check/resource", GoldenDir: "check-resource-v1",
	},
	PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1: {
		ID: PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, Name: "check-resource-bulk-v1", HTTPMethod: "POST",
		PathTmpl: "/access/v1/check/resource/bulk", GoldenDir: "check-resource-bulk-v1",
		SortSlices: true,
	},
	PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1: {
		ID: PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1, Name: "check-resource-bulk-operations-v1", HTTPMethod: "POST",
		PathTmpl: "/access/v1/check/resource/bulk/operations", GoldenDir: "check-resource-bulk-operations-v1",
		SortSlices: true,
	},
	PSUITE_ROW_5_PREVIEW_BULK_OPERATIONS_V1: {
		ID: PSUITE_ROW_5_PREVIEW_BULK_OPERATIONS_V1, Name: "preview-bulk-operations-v1", HTTPMethod: "POST",
		PathTmpl: "/preview/v1/check/resource/bulk/operations", GoldenDir: "preview-bulk-operations-v1",
		SortSlices: true,
	},
	PSUITE_ROW_6_CHECK_FILTER_V1: {
		ID: PSUITE_ROW_6_CHECK_FILTER_V1, Name: "check-filter-v1", HTTPMethod: "POST",
		PathTmpl: "/access/v1/check/filter", GoldenDir: "check-filter-v1",
	},
	PSUITE_ROW_7_CHECK_RESOURCE_V2: {
		ID: PSUITE_ROW_7_CHECK_RESOURCE_V2, Name: "check-resource-v2", HTTPMethod: "POST",
		PathTmpl: "/access/v2/check/resource", GoldenDir: "check-resource-v2",
		IgnoreObligations: true,
	},
	PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2: {
		ID: PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2, Name: "check-resource-bulk-operations-v2", HTTPMethod: "POST",
		PathTmpl: "/access/v2/check/resource/bulk/operations", GoldenDir: "check-resource-bulk-operations-v2",
		IgnoreObligations: true, SortSlices: true,
	},
	PSUITE_ROW_9_PREVIEW_BULK_OPERATIONS_V2: {
		ID: PSUITE_ROW_9_PREVIEW_BULK_OPERATIONS_V2, Name: "preview-bulk-operations-v2", HTTPMethod: "POST",
		PathTmpl: "/preview/v2/check/resource/bulk/operations", GoldenDir: "preview-bulk-operations-v2",
		IgnoreObligations: true, SortSlices: true,
	},
	PSUITE_ROW_10_CHECK_FILTER_V2: {
		ID: PSUITE_ROW_10_CHECK_FILTER_V2, Name: "check-filter-v2", HTTPMethod: "POST",
		PathTmpl: "/access/v2/check/filter", GoldenDir: "check-filter-v2",
		IgnoreObligations: true,
	},
}

// Meta returns a copy of the row metadata for the given id; panics on
// unknown id to fail fast in replay tests rather than silently falling
// through to a zero-value row.
func Meta(id ParityEndpointID) RowMeta {
	m, ok := rowMetas[id]
	if !ok {
		panic(fmt.Sprintf("paritysuite: unknown ParityEndpointID %d", int(id)))
	}
	return m
}

// NewGoldenTarget returns a fresh zero-value pointer that the
// GoldenComparator unmarshals both the golden JSON and the actual response
// into per D-M. CLANG / AGG / SUB / ENT rows reuse the row id they inherit
// from the parity-contract row they live on, so this map covers them
// transitively — no extra ids are needed.
func NewGoldenTarget(id ParityEndpointID) any {
	switch id {
	case PSUITE_ROW_1_API_VERSION:
		return &model.ApiVersionResponse{}
	case PSUITE_ROW_2_CHECK_RESOURCE_V1:
		var decision bool
		return &decision
	case PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1:
		return &[]string{}
	case PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1,
		PSUITE_ROW_5_PREVIEW_BULK_OPERATIONS_V1:
		return &map[string][]string{}
	case PSUITE_ROW_6_CHECK_FILTER_V1:
		return &model.OldFilterEvaluationResult{}
	case PSUITE_ROW_7_CHECK_RESOURCE_V2:
		return &model.CheckResourceResponse{}
	case PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2,
		PSUITE_ROW_9_PREVIEW_BULK_OPERATIONS_V2:
		return &model.CheckResourcesResponse{}
	case PSUITE_ROW_10_CHECK_FILTER_V2:
		return &model.FilterResponse{}
	}
	panic(fmt.Sprintf("paritysuite: no golden factory for ParityEndpointID %d", int(id)))
}
