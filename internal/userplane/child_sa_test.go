package userplane

import (
	"bytes"
	"net"
	"testing"

	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/esn"
	"github.com/free5gc/ike/security/integ"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
)

func TestBuildChildSADirectionWhenN3IWFInitiates(t *testing.T) {
	esnInfo, err := esn.StrToType(esn.String_ESN_DISABLE)
	if err != nil {
		t.Fatal(err)
	}
	i2rEncryption := bytes.Repeat([]byte{0x11}, 32)
	i2rIntegrity := bytes.Repeat([]byte{0x12}, 20)
	r2iEncryption := bytes.Repeat([]byte{0x21}, 32)
	r2iIntegrity := bytes.Repeat([]byte{0x22}, 20)
	child := &n3iwf_context.ChildSecurityAssociation{
		InboundSPI: 0x01020304, OutboundSPI: 0x05060708,
		LocalPublicIPAddr:     net.ParseIP("192.168.2.2"),
		PeerPublicIPAddr:      net.ParseIP("192.168.2.1"),
		TrafficSelectorLocal:  net.IPNet{IP: net.ParseIP("10.0.0.1")},
		TrafficSelectorRemote: net.IPNet{IP: net.ParseIP("10.0.0.2")},
		SelectedIPProtocol:    47,
		LocalIsInitiator:      true,
		ChildSAKey: &ike_security.ChildSAKey{
			EncrKInfo:                         encr.StrToKType("ENCR_AES_CBC_256"),
			IntegKInfo:                        integ.StrToKType("AUTH_HMAC_SHA1_96"),
			EsnInfo:                           esnInfo,
			InitiatorToResponderEncryptionKey: i2rEncryption,
			InitiatorToResponderIntegrityKey:  i2rIntegrity,
			ResponderToInitiatorEncryptionKey: r2iEncryption,
			ResponderToInitiatorIntegrityKey:  r2iIntegrity,
		},
	}

	sa, err := BuildChildSA(1, 1, child)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa.InboundEncryptionKey, r2iEncryption) ||
		!bytes.Equal(sa.InboundIntegrityKey, r2iIntegrity) ||
		!bytes.Equal(sa.OutboundEncryptionKey, i2rEncryption) ||
		!bytes.Equal(sa.OutboundIntegrityKey, i2rIntegrity) {
		t.Fatal("N3IWF-initiated Child SA keys have incorrect dataplane direction")
	}
	if sa.ReplayWindow != dataPlaneReplayWindow {
		t.Fatalf("unexpected dataplane replay window: got %d, want %d",
			sa.ReplayWindow, dataPlaneReplayWindow)
	}

	// The control payload must own its copies; clearing it must not erase the
	// negotiated IKE context used during rekey overlap.
	ClearChildSAKeys(&sa)
	if !bytes.Equal(child.ResponderToInitiatorEncryptionKey, r2iEncryption) ||
		!bytes.Equal(child.InitiatorToResponderEncryptionKey, i2rEncryption) {
		t.Fatal("clearing the contract key copy modified the IKE Child SA")
	}
}
