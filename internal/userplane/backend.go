package userplane

import (
	"context"
	"fmt"

	n3iwfdp "github.com/nycu-ucr/l25gc-n3iwf-dp-client"
)

const (
	BackendLinux = "linux"
	BackendONVM  = "onvm"
)

// Session is the versioned N3DP session object. It is aliased here so the
// N3IWF procedure code depends on its user-plane backend, not directly on a
// particular control transport.
type Session = n3iwfdp.Session
type ChildSA = n3iwfdp.ChildSA

// Backend owns the N3IWF user-plane and Child-SA lifecycle synchronization.
type Backend interface {
	Name() string
	UsesKernelDataPlane() bool
	Start(context.Context) error
	UpsertSession(context.Context, uint64, Session) error
	DeleteSession(context.Context, uint64, uint64, uint32) error
	UpsertChildSA(context.Context, uint64, ChildSA) error
	DeleteChildSA(context.Context, uint64, uint64, uint32, uint32) error
	Close() error
}

type linuxBackend struct{}

func (linuxBackend) Name() string                { return BackendLinux }
func (linuxBackend) UsesKernelDataPlane() bool   { return true }
func (linuxBackend) Start(context.Context) error { return nil }
func (linuxBackend) Close() error                { return nil }
func (linuxBackend) UpsertSession(context.Context, uint64, Session) error {
	return nil
}
func (linuxBackend) DeleteSession(context.Context, uint64, uint64, uint32) error {
	return nil
}
func (linuxBackend) UpsertChildSA(context.Context, uint64, ChildSA) error { return nil }
func (linuxBackend) DeleteChildSA(context.Context, uint64, uint64, uint32, uint32) error {
	return nil
}

type controlClient interface {
	Hello(context.Context) error
	UpsertSession(context.Context, uint64, n3iwfdp.Session) error
	DeleteSession(context.Context, uint64, uint64, uint32) error
	UpsertChildSA(context.Context, uint64, n3iwfdp.ChildSA) error
	DeleteChildSA(context.Context, uint64, uint64, uint32, uint32) error
	Close() error
}

type onvmBackend struct {
	client controlClient
}

func (onvmBackend) Name() string              { return BackendONVM }
func (onvmBackend) UsesKernelDataPlane() bool { return false }
func (b onvmBackend) Start(ctx context.Context) error {
	if err := b.client.Hello(ctx); err != nil {
		return fmt.Errorf("N3IWF-DP hello failed: %w", err)
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

func New(kind, socketPath string) (Backend, error) {
	switch kind {
	case "", BackendLinux:
		return linuxBackend{}, nil
	case BackendONVM:
		if socketPath == "" {
			return nil, fmt.Errorf("ONVM user-plane backend requires n3iwfDpControlSocket")
		}
		return onvmBackend{client: n3iwfdp.New(socketPath)}, nil
	default:
		return nil, fmt.Errorf("unsupported N3IWF user-plane backend %q", kind)
	}
}
