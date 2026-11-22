package scanner

import "github.com/0x3df/LLMHound/internal/discovery"

// WithCollectFault injects a collector error for chosen targets (tests only).
func WithCollectFault(f func(surface discovery.Surface, host string) error) Option {
	return func(s *Scanner) { s.collectFault = f }
}
