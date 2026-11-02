package userplane

import (
	"context"
	"fmt"

	n3iwfup "github.com/nycu-ucr/l25gc-n3iwf-up-client"
)

// Session is the versioned N3DP session object. It is aliased here so the
// N3IWF procedure code depends on its user-plane backend, not directly on a
// particular control transport.
type Session = n3iwfup.Session
type ChildSA = n3iwfup.ChildSA

// Backend owns ONVM/DPDK user-plane and Child-SA lifecycle synchronization.
type Backend interface {
	Start(context.Context) error
	UpsertSession(context.Context, uint64, Session) error
	DeleteSession(context.Context, uint64, uint64, uint32) error
	UpsertChildSA(context.Context, uint64, ChildSA) error
	DeleteChildSA(context.Context, uint64, uint64, uint32, uint32) error
	Close() error
}

type controlClient interface {
	Hello(context.Context) error
	UpsertSession(context.Context, uint64, n3iwfup.Session) error
	DeleteSession(context.Context, uint64, uint64, uint32) error
	UpsertChildSA(context.Context, uint64, n3iwfup.ChildSA) error
	DeleteChildSA(context.Context, uint64, uint64, uint32, uint32) error
	Close() error
}

type onvmBackend struct {
	client controlClient
}

func (b onvmBackend) Start(ctx context.Context) error {
	if err := b.client.Hello(ctx); err != nil {
		return fmt.Errorf("N3IWF-UP hello failed: %w", err)
	}
	return nil
}
func (b onvmBackend) UpsertSession(ctx context.Context, generation uint64, session Session) error {
	return b.client.UpsertSession(ctx, generation, session)
}
func (b onvmBackend) DeleteSession(
	ctx context.Context,
	generation uint64,
	ueID uint64,
	pduSessionID uint32,
) error {
	return b.client.DeleteSession(ctx, generation, ueID, pduSessionID)
}
func (b onvmBackend) UpsertChildSA(ctx context.Context, generation uint64, sa ChildSA) error {
	return b.client.UpsertChildSA(ctx, generation, sa)
}
func (b onvmBackend) DeleteChildSA(ctx context.Context, generation, ueID uint64,
	pduSessionID, inboundSPI uint32) error {
	return b.client.DeleteChildSA(ctx, generation, ueID, pduSessionID, inboundSPI)
}
func (b onvmBackend) Close() error { return b.client.Close() }

type ControlOptions = n3iwfup.Options

func New(controlName string) (Backend, error) {
	return NewWithOptions(ControlOptions{ControlName: controlName})
}

func NewWithOptions(options ControlOptions) (Backend, error) {
	if options.ControlName == "" {
		return nil, fmt.Errorf("N3IWF user plane requires n3iwfUpControlName")
	}
	return onvmBackend{client: n3iwfup.NewWithOptions(options)}, nil
}
