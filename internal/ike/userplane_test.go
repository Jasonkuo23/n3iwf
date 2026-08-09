package ike

import (
	"context"
	"net"
	"testing"

	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/esn"
	"github.com/free5gc/ike/security/integ"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/userplane"
)

func makeTestChildSA(t *testing.T, ikeUe *n3iwf_context.N3IWFIkeUe) *n3iwf_context.ChildSecurityAssociation {
	t.Helper()
	esnInfo, err := esn.StrToType(esn.String_ESN_DISABLE)
	if err != nil {
		t.Fatal(err)
	}
	return &n3iwf_context.ChildSecurityAssociation{
		InboundSPI: 1001, OutboundSPI: 1002,
		LocalPublicIPAddr:     net.ParseIP("192.168.127.1"),
		PeerPublicIPAddr:      net.ParseIP("192.168.127.2"),
		TrafficSelectorLocal:  net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(32, 32)},
		TrafficSelectorRemote: net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32)},
		SelectedIPProtocol:    47, IkeUE: ikeUe, LocalIsInitiator: true,
		ChildSAKey: &ike_security.ChildSAKey{
			EncrKInfo:  encr.StrToKType("ENCR_AES_CBC_128"),
			IntegKInfo: integ.StrToKType("AUTH_HMAC_SHA1_96"), EsnInfo: esnInfo,
			InitiatorToResponderEncryptionKey: make([]byte, 16),
			ResponderToInitiatorEncryptionKey: make([]byte, 16),
			InitiatorToResponderIntegrityKey:  make([]byte, 20),
			ResponderToInitiatorIntegrityKey:  make([]byte, 20),
		},
	}
}

type recordingUserPlane struct {
	upserts         int
	childUpserts    int
	generation      uint64
	childGeneration uint64
	session         userplane.Session
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
func (r *recordingUserPlane) UpsertChildSA(_ context.Context, generation uint64, _ userplane.ChildSA) error {
	r.childUpserts++
	r.childGeneration = generation
	return nil
}
func (*recordingUserPlane) DeleteChildSA(context.Context, uint64, uint64, uint32, uint32) error {
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

	childSA := makeTestChildSA(t, ikeUe)
	if err := server.upsertPDUSessionUserPlane(42, pduSession, ikeUe, childSA); err != nil {
		t.Fatal(err)
	}
	if recorder.childUpserts != 1 || recorder.childGeneration != 1 ||
		recorder.upserts != 1 || recorder.generation != 2 ||
		recorder.session.UEID != 42 || recorder.session.UplinkTEID != 100 ||
		recorder.session.DownlinkTEID != 200 {
		t.Fatalf("unexpected upsert: %+v", recorder)
	}
}
