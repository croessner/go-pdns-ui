package audit

import "context"

// SearchParams defines filters for querying the audit log.
type SearchParams struct {
	Query  string
	Action string
	Page   int
	Limit  int
}

// SearchResult holds a page of audit entries and pagination metadata.
type SearchResult struct {
	Entries    []Entry
	Total      int
	Page       int
	TotalPages int
}

// Service provides audit log persistence and retrieval.
type Service interface {
	// Enabled reports whether audit logging is active.
	Enabled() bool

	// Log persists a single audit entry.
	Log(ctx context.Context, entry Entry) error

	// Search returns a paginated, filtered list of audit entries.
	Search(ctx context.Context, params SearchParams) (SearchResult, error)

	// Actions returns the distinct action values stored in the log.
	Actions(ctx context.Context) ([]string, error)

	// Close releases resources held by the service.
	Close() error
}

// NoopService is a no-op implementation used when audit logging is disabled.
type NoopService struct{}

func NewNoopService() Service { return &NoopService{} }

func (s *NoopService) Enabled() bool                                         { return false }
func (s *NoopService) Log(_ context.Context, _ Entry) error                  { return nil }
func (s *NoopService) Search(_ context.Context, _ SearchParams) (SearchResult, error) {
	return SearchResult{Page: 1, TotalPages: 1}, nil
}
func (s *NoopService) Actions(_ context.Context) ([]string, error) { return nil, nil }
func (s *NoopService) Close() error                                { return nil }
