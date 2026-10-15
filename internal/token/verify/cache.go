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
	"sync"
	"time"
)

// cache keeps verified tokens by the SHA-256 digest of their compact form
// until they expire. It holds at most max tokens. A token whose digest is
// already kept replaces that entry. Any other token that arrives while the
// cache is full sweeps out the expired entries first, and is not kept when
// none has expired; a full cache sweeps no more often than its earliest
// expiry, so an entry that expires before then stays until the next sweep.
type cache struct {
	mu      sync.RWMutex
	entries map[[sha256.Size]byte]*Token
	max     int
	// nextExpiry is the earliest time a kept token expires, as the last
	// sweep found it; a full cache is not swept again before it.
	nextExpiry time.Time
}

func newCache(size int) *cache {
	return &cache{entries: make(map[[sha256.Size]byte]*Token), max: size}
}

// get returns the token kept under digest, or nil when there is none or it
// has expired at now.
func (c *cache) get(digest [sha256.Size]byte, now time.Time, leeway time.Duration) *Token {
	c.mu.RLock()
	tok := c.entries[digest]
	c.mu.RUnlock()
	if tok == nil || !now.Before(tok.Expiry.Add(leeway)) {
		return nil
	}
	return tok
}

func (c *cache) put(digest [sha256.Size]byte, tok *Token, now time.Time, leeway time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, kept := c.entries[digest]; kept {
		c.entries[digest] = tok
		return
	}
	if len(c.entries) >= c.max {
		if now.Before(c.nextExpiry) {
			return
		}
		c.nextExpiry = time.Time{}
		for d, kept := range c.entries {
			expiry := kept.Expiry.Add(leeway)
			if !now.Before(expiry) {
				delete(c.entries, d)
				continue
			}
			if c.nextExpiry.IsZero() || expiry.Before(c.nextExpiry) {
				c.nextExpiry = expiry
			}
		}
		if len(c.entries) >= c.max {
			return
		}
	}
	c.entries[digest] = tok
}
