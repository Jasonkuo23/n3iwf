package ike

import (
	"context"
	"net"
	"testing"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/userplane"
)

type recordingUserPlane struct {
	upserts    int
	generation uint64
	session    userplane.Session
}

func (*recordingUserPlane) Name() string                { return userplane.BackendONVM }
func (*recordingUserPlane) UsesKernelDataPlane() bool   { return false }
func (*recordingUserPlane) Start(context.Context) error { return nil }
func (r *recordingUserPlane) UpsertSession(
	_ context.Context,
	generation uint64,
	session userplane.Session,
) error {
	r.upserts++
	r.generation = generation
	r.session = session
	return nil
}
func (*recordingUserPlane) DeleteSession(context.Context, uint64, uint64, uint32) error {
	return nil
}
func (*recordingUserPlane) Close() error { return nil }

func TestUpsertPDUSessionUserPlane(t *testing.T) {
	app, err := NewN3iwfTestApp(NewTestCfg())
	if err != nil {
		t.Fatal(err)
	}
	app.cfg.Configuration.IPSecGatewayAddr = "10.0.0.1"
	app.cfg.Configuration.N3IWFGTPBindAddress = "192.168.2.1"
	recorder := &recordingUserPlane{}
	app.userPlane = recorder
	server, err := NewServer(app)
	if err != nil {
		t.Fatal(err)
	}
	pduSession := &n3iwf_context.PDUSession{
		Id:      10,
		QFIList: []uint8{9},
		GTPConnInfo: &n3iwf_context.GTPConnectionInfo{
			UPFIPAddr:    "192.168.2.2",
			IncomingTEID: 200,
			OutgoingTEID: 100,
		},
	}
	ikeUe := &n3iwf_context.N3IWFIkeUe{IPSecInnerIP: net.ParseIP("10.0.0.2")}

	if err := server.upsertPDUSessionUserPlane(42, pduSession, ikeUe); err != nil {
		t.Fatal(err)
	}
	if recorder.upserts != 1 || recorder.generation != 1 ||
		recorder.session.UEID != 42 || recorder.session.UplinkTEID != 100 ||
		recorder.session.DownlinkTEID != 200 {
		t.Fatalf("unexpected upsert: %+v", recorder)
	}
}
