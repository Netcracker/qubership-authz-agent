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

package verify

import (
	"encoding/json"
	"math"
	"slices"
	"time"

	"authz-agent/internal/token/keys"
)

// maxNumericDate is the largest magnitude exp, nbf, and iat may have, in
// seconds: 2^53 - 1 (9007199254740991), the integer range I-JSON (RFC 7493)
// allows. Past it a float64 no longer holds every whole second, so the
// time read could differ from the one the provider wrote.
const maxNumericDate = 1<<53 - 1

// checkTimes checks exp, which is required, then nbf and iat, which are
// optional, against now with leeway either way, and returns the time exp
// names.
func checkTimes(claims map[string]any, now time.Time, leeway time.Duration) (time.Time, error) {
	exp, present, err := numericDate(claims, "exp")
	if err != nil {
		return time.Time{}, err
	}
	if !present {
		return time.Time{}, fail(CodeExpMissing, "token has no exp claim")
	}
	if !now.Before(exp.Add(leeway)) {
		return time.Time{}, fail(CodeExpired, "token expired at %s", exp.UTC().Format(time.RFC3339))
	}
	nbf, present, err := numericDate(claims, "nbf")
	if err != nil {
		return time.Time{}, err
	}
	if present && now.Before(nbf.Add(-leeway)) {
		return time.Time{}, fail(CodeNotYetValid, "token is not valid before %s", nbf.UTC().Format(time.RFC3339))
	}
	iat, present, err := numericDate(claims, "iat")
	if err != nil {
		return time.Time{}, err
	}
	if present && iat.After(now.Add(leeway)) {
		return time.Time{}, fail(CodeIATInvalid, "token was issued at %s, in the future", iat.UTC().Format(time.RFC3339))
	}
	return exp, nil
}

// numericDate reads the claim name as a number of seconds since the epoch;
// present is false when the payload has no such claim.
func numericDate(claims map[string]any, name string) (t time.Time, present bool, err error) {
	raw, ok := claims[name]
	if !ok {
		return time.Time{}, false, nil
	}
	n, ok := raw.(json.Number)
	if !ok {
		return time.Time{}, true, fail(CodeFormatInvalid, "claim %s is not a number", name)
	}
	seconds, err := n.Float64()
	if err != nil || math.Abs(seconds) > maxNumericDate {
		return time.Time{}, true, fail(CodeFormatInvalid, "claim %s is %s, outside ±%d seconds", name, short(n.String()), int64(maxNumericDate))
	}
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(fraction*float64(time.Second))), true, nil
}

// checkAudience applies the audiences of the provider p. With none listed,
// every token passes. Otherwise aud, a string or an array of strings, has to
// name one of them exactly, and a token without aud passes only when p sets
// AllowMissingAud.
func checkAudience(claims map[string]any, p *keys.Provider) error {
	if len(p.Audiences) == 0 {
		return nil
	}
	raw, present := claims["aud"]
	if !present {
		if p.AllowMissingAud {
			return nil
		}
		return fail(CodeAudienceMissing, "token has no aud claim, and provider %q requires one of %q", p.ID, p.Audiences)
	}
	var audiences []string
	switch v := raw.(type) {
	case string:
		audiences = []string{v}
	case []any:
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return fail(CodeAudienceInvalid, "aud holds a value that is not a string")
			}
			audiences = append(audiences, s)
		}
	default:
		return fail(CodeAudienceInvalid, "aud is neither a string nor an array of strings")
	}
	for _, aud := range audiences {
		if slices.Contains(p.Audiences, aud) {
			return nil
		}
	}
	return fail(CodeAudienceInvalid, "aud %s names none of %q, the audiences of provider %q", shortList(audiences), p.Audiences, p.ID)
}
