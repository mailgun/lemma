package httpsign

import (
	"sync"

	"github.com/mailgun/timetools"
	"github.com/mailgun/ttlmap"
)

type NonceCache struct {
	sync.Mutex
	cache        *ttlmap.TtlMap
	cacheTTL     int
	timeProvider timetools.TimeProvider
}

// Return a new NonceCache. Allows you to control cache capacity, ttl, as well as the TimeProvider.
func NewNonceCache(capacity int, cacheTTL int, timeProvider timetools.TimeProvider) (*NonceCache, error) {
	c, err := ttlmap.NewMapWithProvider(capacity, timeProvider)
	if err != nil {
		return nil, err
	}

	return &NonceCache{
		cache:        c,
		cacheTTL:     cacheTTL,
		timeProvider: timeProvider,
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
