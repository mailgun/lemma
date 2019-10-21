package httpsign

import (
	"sync"

	"github.com/mailgun/holster/v3/collections"
)

type NonceCache struct {
	sync.Mutex

	cache    *collections.TTLMap
	cacheTTL int
}

// Return a new NonceCache. Allows you to control cache capacity, ttl, as well as the TimeProvider.
func NewNonceCache(capacity int, cacheTTL int) (*NonceCache, error) {
	return &NonceCache{
		cache:    collections.NewTTLMap(capacity),
		cacheTTL: cacheTTL,
	}, nil
}

// InCache checks if a nonce is in the cache. If not, it adds it to the
// cache and returns false. Otherwise it returns true.
func (n *NonceCache) InCache(nonce string) bool {
	n.Lock()
	defer n.Unlock()

	// check if the nonce is already in the cache
	_, exists := n.cache.Get(nonce)
	if exists {
		return true
	}

	// it's not, so let's put it in the cache
	n.cache.Set(nonce, "", n.cacheTTL)

	return false
}
