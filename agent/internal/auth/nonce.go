package auth

import (
	"sync"
	"time"
)

// nonceCache remembers recently-seen request nonces so that a captured, validly
// signed request cannot be replayed within the acceptance window. Entries are
// kept only as long as a request bearing them could still pass the timestamp
// check; expired entries are swept lazily.
type nonceCache struct {
	ttl time.Duration
	now func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time // nonce -> expiry
}

func newNonceCache(ttl time.Duration, now func() time.Time) *nonceCache {
	return &nonceCache{ttl: ttl, now: now, seen: make(map[string]time.Time)}
}

// use records nonce and reports whether it was fresh. A false result means the
// nonce has already been used within the window and the request must be
// rejected as a replay.
func (n *nonceCache) use(nonce string) bool {
	now := n.now()
	n.mu.Lock()
	defer n.mu.Unlock()

	n.sweepLocked(now)
	if _, exists := n.seen[nonce]; exists {
		return false
	}
	n.seen[nonce] = now.Add(n.ttl)
	return true
}

func (n *nonceCache) sweepLocked(now time.Time) {
	for k, expiry := range n.seen {
		if now.After(expiry) {
			delete(n.seen, k)
		}
	}
}
