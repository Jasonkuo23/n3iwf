package userplane

import (
	"net"
	"testing"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
)

func TestBuildSession(t *testing.T) {
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

	session, err := BuildSession(42, pduSession, ikeUe, "10.0.0.1", "192.168.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if session.UEID != 42 || session.PDUSessionID != 10 ||
		session.UplinkTEID != 100 || session.DownlinkTEID != 200 ||
		!session.UENWuAddress.Equal(net.ParseIP("10.0.0.2")) ||
		!session.UPFN3Address.Equal(net.ParseIP("192.168.2.2")) ||
		len(session.QFIs) != 1 || session.QFIs[0] != 9 {
		t.Fatalf("unexpected session: %+v", session)
	}
	if !session.UEPDUAddress.Equal(net.IPv4zero) {
		t.Fatalf("UE PDU address must be unspecified, got %s", session.UEPDUAddress)
	}
}

func TestBuildSessionRejectsIncompleteScope(t *testing.T) {
	pduSession := &n3iwf_context.PDUSession{
		Id:      10,
		QFIList: []uint8{5, 9},
		GTPConnInfo: &n3iwf_context.GTPConnectionInfo{
			UPFIPAddr:    "192.168.2.2",
			IncomingTEID: 200,
			OutgoingTEID: 100,
		},
	}
	ikeUe := &n3iwf_context.N3IWFIkeUe{IPSecInnerIP: net.ParseIP("10.0.0.2")}
	if _, err := BuildSession(42, pduSession, ikeUe, "10.0.0.1", "192.168.2.1"); err == nil {
		t.Fatal("multi-QFI session accepted")
	}
}
