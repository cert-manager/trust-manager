package bundle

import "sync"

// etagCache holds the responses to HTTPS bundle sources, with their etags and date.
type etagCache struct {
	cache map[string]dataWithEtag
	sync.RWMutex
}

type dataWithEtag struct {
	etag, date string
	data       []byte
}

func newEtagCache() *etagCache {
	return &etagCache{
		cache: make(map[string]dataWithEtag),
	}
}
