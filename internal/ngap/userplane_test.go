package ngap

import (
	"context"
	"testing"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/userplane"
	"github.com/free5gc/n3iwf/pkg/factory"
)

type recordingDeleteUserPlane struct {
	deletes      int
	generation   uint64
	ueID         uint64
	pduSessionID uint32
}

func (*recordingDeleteUserPlane) Name() string                { return userplane.BackendONVM }
func (*recordingDeleteUserPlane) UsesKernelDataPlane() bool   { return false }
func (*recordingDeleteUserPlane) Start(context.Context) error { return nil }
func (*recordingDeleteUserPlane) UpsertSession(context.Context, uint64, userplane.Session) error {
	return nil
}
func (r *recordingDeleteUserPlane) DeleteSession(
	_ context.Context,
	generation uint64,
	ueID uint64,
	pduSessionID uint32,
) error {
	r.deletes++
	r.generation = generation
	r.ueID = ueID
	r.pduSessionID = pduSessionID
	return nil
}
func (*recordingDeleteUserPlane) UpsertChildSA(context.Context, uint64, userplane.ChildSA) error {
	return nil
}
func (*recordingDeleteUserPlane) DeleteChildSA(context.Context, uint64, uint64, uint32, uint32) error {
	return nil
}
func (*recordingDeleteUserPlane) Close() error { return nil }

func TestDeletePDUSessionUserPlane(t *testing.T) {
	app, err := NewN3iwfTestApp(&factory.Config{Configuration: &factory.Configuration{}})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingDeleteUserPlane{}
	app.userPlane = recorder
	server, err := NewServer(app)
	if err != nil {
		t.Fatal(err)
	}
	pduSession := &n3iwf_context.PDUSession{Id: 10}
	if _, err := pduSession.NextUserPlaneGeneration(); err != nil {
		t.Fatal(err)
	}

	if err := server.deletePDUSessionUserPlane(42, pduSession); err != nil {
		t.Fatal(err)
	}
	if recorder.deletes != 1 || recorder.generation != 2 ||
		recorder.ueID != 42 || recorder.pduSessionID != 10 {
		t.Fatalf("unexpected delete: %+v", recorder)
	}
}
