package scanner

import "fmt"

// Registry manages scanner modules by name.
type Registry struct {
	scanners map[string]Scanner
}

// NewRegistry creates an empty scanner registry.
func NewRegistry() *Registry {
	return &Registry{scanners: make(map[string]Scanner)}
}

// Register adds a scanner to the registry.
func (r *Registry) Register(s Scanner) {
	r.scanners[s.Name()] = s
}

// Get retrieves a scanner by name.
func (r *Registry) Get(name string) (Scanner, error) {
	s, ok := r.scanners[name]
	if !ok {
		return nil, fmt.Errorf("scanner %q not found", name)
	}
	return s, nil
}

// All returns all registered scanners.
func (r *Registry) All() []Scanner {
	result := make([]Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		result = append(result, s)
	}
	return result
}
