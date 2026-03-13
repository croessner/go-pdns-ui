package audit

import "time"

// Entry represents a single audit log record persisted to the database.
type Entry struct {
	ID         string
	Timestamp  time.Time
	Action     string
	User       string
	Role       string
	AuthSource string
	Target     string
	Detail     string
}
