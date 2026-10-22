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
	"crypto/sha256"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// cache keeps verified tokens by the SHA-256 digest of their compact form
// until they expire. It holds at most the number of tokens newCache was
// given; a token that arrives while it is full takes the place of the
// token used least recently. It is safe for concurrent use.
type cache struct {
	tokens *lru.Cache[[sha256.Size]byte, *Token]
}

// newCache returns an empty cache for size tokens; size has to be positive.
func newCache(size int) *cache {
	tokens, _ := lru.New[[sha256.Size]byte, *Token](size)
	return &cache{tokens: tokens}
}

// get returns the token kept under digest, or nil when there is none or it
// has expired at now. An expired token leaves the cache.
func (c *cache) get(digest [sha256.Size]byte, now time.Time, leeway time.Duration) *Token {
	tok, ok := c.tokens.Get(digest)
	if !ok {
		return nil
	}
	if !now.Before(tok.expiry.Add(leeway)) {
		c.tokens.Remove(digest)
		return nil
	}
	return tok
}

// put keeps tok under digest, in place of a token kept under it before.
func (c *cache) put(digest [sha256.Size]byte, tok *Token) {
	c.tokens.Add(digest, tok)
}
