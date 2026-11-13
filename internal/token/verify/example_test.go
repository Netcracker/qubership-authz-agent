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

package verify_test

import (
	"context"
	"fmt"

	"authz-agent/internal/token/keys"
	"authz-agent/internal/token/tokentest"
	"authz-agent/internal/token/verify"
)

// A test outside these packages signs a token with a [tokentest.Issuer] and
// sends it through the real key loading and the real checks.
func ExampleVerifier_Verify() {
	issuer := tokentest.NewIssuer()
	defer issuer.Close()
	ctx := context.Background()

	set, err := keys.New(issuer.RealmConfig(), keys.Options{})
	if err != nil {
		fmt.Println(err)
		return
	}
	verifier := verify.New(set, verify.Options{})

	claims := issuer.Claims()
	claims["iss"] = issuer.RealmURL()
	claims["level"] = "m2m"
	tok, err := verifier.Verify(ctx, issuer.Sign(claims))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(tok.ProviderID(), tok.Kind(), tok.IsM2M())

	delete(claims, "exp")
	_, err = verifier.Verify(ctx, issuer.Sign(claims))
	fmt.Println(err)
	// Output:
	// realm/test realm true
	// TOKEN_EXP_MISSING: token has no exp claim
}
