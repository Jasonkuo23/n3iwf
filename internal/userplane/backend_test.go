package userplane

import (
	"context"
	"errors"
	"net"
	"testing"

	n3iwfdp "github.com/nycu-ucr/l25gc-n3iwf-dp-client"
)

type fakeControlClient struct {
	helloErr       error
	helloCalls     int
	upsertCalls    int
	deleteCalls    int
	closeCalls     int
	lastGeneration uint64
}

func (f *fakeControlClient) Hello(context.Context) error {
	f.helloCalls++
	return f.helloErr
}

func (f *fakeControlClient) UpsertSession(
	_ context.Context,
	generation uint64,
	_ n3iwfdp.Session,
) error {
	f.upsertCalls++
	f.lastGeneration = generation
	return nil
}

func (f *fakeControlClient) DeleteSession(
	_ context.Context,
	generation uint64,
	_ uint64,
	_ uint32,
) error {
	f.deleteCalls++
	f.lastGeneration = generation
	return nil
}
func (f *fakeControlClient) UpsertChildSA(_ context.Context, generation uint64,
	_ n3iwfdp.ChildSA) error {
	f.upsertCalls++
	f.lastGeneration = generation
	return nil
}
func (f *fakeControlClient) DeleteChildSA(_ context.Context, generation, _ uint64,
	_, _ uint32) error {
	f.deleteCalls++
	f.lastGeneration = generation
	return nil
}

func (f *fakeControlClient) Close() error {
	f.closeCalls++
	return nil
}

func TestNewRequiresControlSocket(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("empty control socket accepted")
	}
}

func TestONVMBackendLifecycle(t *testing.T) {
	fake := &fakeControlClient{}
	backend := onvmBackend{client: fake}
	ctx := context.Background()

	if err := backend.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := backend.UpsertSession(ctx, 4, Session{
		UEID:         1,
		PDUSessionID: 10,
		UplinkTEID:   100,
		DownlinkTEID: 200,
		UEPDUAddress: net.IPv4zero,
		QFIs:         []uint8{9},
	}); err != nil {
		t.Fatal(err)
	}
	if err := backend.DeleteSession(ctx, 5, 1, 10); err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	if fake.helloCalls != 1 || fake.upsertCalls != 1 ||
		fake.deleteCalls != 1 || fake.closeCalls != 1 ||
		fake.lastGeneration != 5 {
		t.Fatalf("unexpected calls: %+v", fake)
	}
}

func TestONVMBackendFailsStartupWhenDataplaneUnavailable(t *testing.T) {
	fake := &fakeControlClient{helloErr: errors.New("unavailable")}
	backend := onvmBackend{client: fake}
	if err := backend.Start(context.Background()); err == nil {
		t.Fatal("ONVM backend started without dataplane acknowledgement")
	}
}
