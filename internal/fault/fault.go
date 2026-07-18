package fault

import "fmt"

// Error is a typed operational error. Its public text intentionally excludes
// the wrapped error so lower-level messages cannot disclose secret values.
type Error struct {
	Kind string
	Op   string
	Err  error
}

func New(op, kind string, err error) *Error {
	return &Error{Op: op, Kind: kind, Err: err}
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Op, e.Kind)
}

func (e *Error) Unwrap() error { return e.Err }
