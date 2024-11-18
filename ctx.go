package blackmail

import "context"

var ctxkey = &struct{ n string }{"blackmail"}

// With returns a copy of the context with the Mailer as a value.
func With(ctx context.Context, m *Mailer) context.Context {
	return context.WithValue(ctx, ctxkey, m)
}

// Get retrieves the Mailer stored on the context with [With], returning nil if
// there is no context stored.
func Get(ctx context.Context) *Mailer {
	m, ok := ctx.Value(ctxkey).(*Mailer)
	if !ok {
		return nil
	}
	return m
}

// MustGet works like [Get], but will panic on errors.
func MustGet(ctx context.Context) *Mailer {
	m := Get(ctx)
	if m == nil {
		panic("blackmail.MustGet: no Mailer on context")
	}
	return m
}
