package ike

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"testing"
	"time"

	ike_message "github.com/free5gc/ike/message"
	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/prf"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/pkg/factory"
	"github.com/free5gc/ngap/ngapType"
)

func rekeyPayloadParts(t *testing.T, payload ike_message.IKEPayloadContainer) (
	*ike_message.Notification,
	*ike_message.SecurityAssociation,
	*ike_message.Nonce,
	*ike_message.TrafficSelectorInitiator,
	*ike_message.TrafficSelectorResponder,
) {
	t.Helper()
	if len(payload) != 5 {
		t.Fatalf("unexpected rekey payload count: %d", len(payload))
	}
	notify, ok := payload[0].(*ike_message.Notification)
	if !ok {
		t.Fatalf("payload[0] is %T, want Notification", payload[0])
	}
	sa, ok := payload[1].(*ike_message.SecurityAssociation)
	if !ok {
		t.Fatalf("payload[1] is %T, want SecurityAssociation", payload[1])
	}
	nonce, ok := payload[2].(*ike_message.Nonce)
	if !ok {
		t.Fatalf("payload[2] is %T, want Nonce", payload[2])
	}
	tsi, ok := payload[3].(*ike_message.TrafficSelectorInitiator)
	if !ok {
		t.Fatalf("payload[3] is %T, want TSi", payload[3])
	}
	tsr, ok := payload[4].(*ike_message.TrafficSelectorResponder)
	if !ok {
		t.Fatalf("payload[4] is %T, want TSr", payload[4])
	}
	return notify, sa, nonce, tsi, tsr
}

func TestBuildAndValidateChildSARekey(t *testing.T) {
	ikeUe := &n3iwf_context.N3IWFIkeUe{}
	old := makeTestChildSA(t, ikeUe)
	old.PDUSessionIds = []int64{1}
	nonceBytes := bytes.Repeat([]byte{0x5a}, 32)
	payload, err := buildChildSARekeyPayload(old, 0x11223344, nonceBytes)
	if err != nil {
		t.Fatal(err)
	}
	notify, sa, nonce, tsi, tsr := rekeyPayloadParts(t, payload)
	if notify.ProtocolID != ike_message.TypeESP ||
		notify.NotifyMessageType != ike_message.REKEY_SA ||
		len(notify.NotificationData) != 0 || len(notify.SPI) != 4 ||
		binary.BigEndian.Uint32(notify.SPI) != old.InboundSPI {
		t.Fatalf("invalid REKEY_SA notification: %+v", notify)
	}
	if !bytes.Equal(nonce.NonceData, nonceBytes) || len(sa.Proposals) != 1 ||
		binary.BigEndian.Uint32(sa.Proposals[0].SPI) != 0x11223344 {
		t.Fatal("request did not retain its nonce/proposed inbound SPI")
	}

	// Turn the offered proposal into the peer's accepted response by replacing
	// only its SPI. Algorithms and exact host selectors remain equivalent.
	sa.Proposals[0].SPI = []byte{0x55, 0x66, 0x77, 0x88}
	spi, err := validateChildSARekeyResponse(old, sa, tsi, tsr)
	if err != nil {
		t.Fatal(err)
	}
	if spi != 0x55667788 {
		t.Fatalf("unexpected peer SPI 0x%08x", spi)
	}

	tsi.TrafficSelectors[0].EndPort = 1024
	if _, err = validateChildSARekeyResponse(old, sa, tsi, tsr); err == nil {
		t.Fatal("narrowed traffic selector was accepted")
	}
}

func TestDiscardHalfChildSAErasesRekeyNonce(t *testing.T) {
	ikeUe := &n3iwf_context.N3IWFIkeUe{
		TemporaryExchangeMsgIDChildSAMapping: make(map[uint32]*n3iwf_context.ChildSecurityAssociation),
		N3IWFChildSecurityAssociation:        make(map[uint32]*n3iwf_context.ChildSecurityAssociation),
		IPSecInnerIP:                         net.ParseIP("10.0.0.2"),
	}
	ikeUe.CreateHalfChildSARekey(7, 100, 1, 99, bytes.Repeat([]byte{0xaa}, 32))
	pending := ikeUe.TemporaryExchangeMsgIDChildSAMapping[7]
	ikeUe.DiscardHalfChildSA(7)
	if _, exists := ikeUe.TemporaryExchangeMsgIDChildSAMapping[7]; exists {
		t.Fatal("pending rekey was not removed")
	}
	if !bytes.Equal(pending.InitiatorNonce, make([]byte, 32)) {
		t.Fatal("pending rekey nonce was not erased")
	}
}

func TestHandleChildSARekeyResponseInstallsOverlap(t *testing.T) {
	app, err := NewN3iwfTestApp(NewTestCfg())
	if err != nil {
		t.Fatal(err)
	}
	defer app.cancel()
	app.cfg.Configuration.IPSecGatewayAddr = "10.0.0.1"
	app.cfg.Configuration.N3IWFGTPBindAddress = "192.168.2.1"
	app.cfg.Configuration.ChildSARekey = &factory.ChildSARekeyConfig{
		Enable: true, Lifetime: time.Hour, OverlapDuration: 30 * time.Minute,
	}
	recorder := &recordingUserPlane{}
	app.userPlane = recorder
	server, err := NewServer(app)
	if err != nil {
		t.Fatal(err)
	}

	ikeSA := app.n3iwfCtx.NewIKESecurityAssociation()
	ikeSA.RemoteSPI = 0x1020304050607080
	ikeSA.ResponderMessageID = 7
	ikeSA.IKESAKey = &ike_security.IKESAKey{
		PrfInfo: prf.StrToType(prf.PRF_HMAC_SHA1),
		Prf_d:   hmac.New(sha1.New, bytes.Repeat([]byte{0x31}, 20)),
	}
	ikeUe := app.n3iwfCtx.NewN3iwfIkeUe(ikeSA.LocalSPI)
	ikeUe.N3IWFIKESecurityAssociation = ikeSA
	ikeSA.IkeUE = ikeUe
	ikeUe.IPSecInnerIP = net.ParseIP("10.0.0.2")

	ranUe := app.n3iwfCtx.NewN3iwfRanUe()
	if ranUe == nil {
		t.Fatal("allocate RAN UE")
	}
	app.n3iwfCtx.IkeSpiNgapIdMapping(ikeSA.LocalSPI, ranUe.RanUeNgapId)
	pduSession, err := ranUe.CreatePDUSession(1, ngapType.SNSSAI{})
	if err != nil {
		t.Fatal(err)
	}
	pduSession.QFIList = []uint8{9}
	pduSession.GTPConnInfo = &n3iwf_context.GTPConnectionInfo{
		UPFIPAddr: "192.168.2.2", IncomingTEID: 200, OutgoingTEID: 100,
	}

	old := makeTestChildSA(t, ikeUe)
	old.PDUSessionIds = []int64{1}
	ikeUe.N3IWFChildSecurityAssociation[old.InboundSPI] = old
	app.n3iwfCtx.ChildSA.Store(old.InboundSPI, old)

	initiatorNonce := bytes.Repeat([]byte{0x41}, 32)
	payload, err := buildChildSARekeyPayload(old, 2001, initiatorNonce)
	if err != nil {
		t.Fatal(err)
	}
	_, sa, _, tsi, tsr := rekeyPayloadParts(t, payload)
	sa.Proposals[0].SPI = []byte{0, 0, 0x0b, 0xba}
	ikeUe.CreateHalfChildSARekey(ikeSA.ResponderMessageID, 2001, 1,
		old.InboundSPI, initiatorNonce)
	ikeSA.OutstandingRequest.Store(true)
	response := ike_message.NewMessage(ikeSA.RemoteSPI, ikeSA.LocalSPI,
		ike_message.CREATE_CHILD_SA, true, false, ikeSA.ResponderMessageID, nil)
	responderNonce := &ike_message.Nonce{NonceData: bytes.Repeat([]byte{0x52}, 32)}

	if handled := server.handleChildSARekeyResponse(response, sa, responderNonce,
		tsi, tsr, nil, ikeSA); !handled {
		t.Fatal("rekey response was not recognized")
	}
	replacement, exists := ikeUe.N3IWFChildSecurityAssociation[2001]
	if !exists || replacement.OutboundSPI != 3002 ||
		replacement.RekeyOfInboundSPI != old.InboundSPI {
		t.Fatalf("replacement Child SA not installed: %+v", replacement)
	}
	if _, exists = ikeUe.N3IWFChildSecurityAssociation[old.InboundSPI]; !exists {
		t.Fatal("old Child SA was removed before overlap retirement")
	}
	if recorder.childUpserts != 1 || recorder.childDeletes != 0 || recorder.deletes != 0 {
		t.Fatalf("unexpected dataplane operations: %+v", recorder)
	}
	if ikeSA.ResponderMessageID != 8 || ikeSA.OutstandingRequest.Load() {
		t.Fatalf("IKE request state was not completed: messageID=%d outstanding=%t",
			ikeSA.ResponderMessageID, ikeSA.OutstandingRequest.Load())
	}

	// Retirement is acknowledgement-driven: both SPIs remain until the
	// INFORMATIONAL response completes the stored Delete transaction.
	if !ikeSA.BeginRekeyRequest(n3iwf_context.RekeyRequestState{
		Kind: n3iwf_context.RekeyDeleteRequest, MessageID: 8,
		OldInboundSPI: old.InboundSPI, NewInboundSPI: replacement.InboundSPI,
		Packet: []byte{1, 2, 3},
	}) {
		t.Fatal("could not start synthetic Delete transaction")
	}
	if _, exists := ikeUe.N3IWFChildSecurityAssociation[old.InboundSPI]; !exists {
		t.Fatal("old Child SA retired before Delete acknowledgement")
	}
	deleteResponse := ike_message.NewMessage(ikeSA.RemoteSPI, ikeSA.LocalSPI,
		ike_message.INFORMATIONAL, true, false, 8, nil)
	if !server.handleRekeyDeleteResponse(deleteResponse, ikeSA) {
		t.Fatal("Delete response was not recognized")
	}
	if _, exists := ikeUe.N3IWFChildSecurityAssociation[old.InboundSPI]; exists {
		t.Fatal("old Child SA survived acknowledged retirement")
	}
	if replacement.RekeyOfInboundSPI != 0 || recorder.childDeletes != 1 {
		t.Fatalf("replacement/retirement state is incomplete: replacement=%+v recorder=%+v",
			replacement, recorder)
	}
}

func TestRetransmitRekeyRequestUsesStoredPacket(t *testing.T) {
	app, err := NewN3iwfTestApp(NewTestCfg())
	if err != nil {
		t.Fatal(err)
	}
	defer app.cancel()
	app.cfg.Configuration.ChildSARekey = &factory.ChildSARekeyConfig{
		Enable: true, Lifetime: 2 * time.Hour, OverlapDuration: time.Hour,
		RetransmitTime: time.Hour, MaxRetransmits: 3,
	}
	server, err := NewServer(app)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	ikeSA := app.n3iwfCtx.NewIKESecurityAssociation()
	ikeUe := app.n3iwfCtx.NewN3iwfIkeUe(ikeSA.LocalSPI)
	ikeUe.N3IWFIKESecurityAssociation = ikeSA
	ikeSA.IkeUE = ikeUe
	ikeSA.IKEConnection = &n3iwf_context.UDPSocketInfo{
		Conn: sender, UEAddr: receiver.LocalAddr().(*net.UDPAddr),
		N3IWFAddr: sender.LocalAddr().(*net.UDPAddr),
	}
	wantPacket := []byte{0xde, 0xad, 0xbe, 0xef}
	if !ikeSA.BeginRekeyRequest(n3iwf_context.RekeyRequestState{
		Kind: n3iwf_context.RekeyCreateRequest, MessageID: 11, Packet: wantPacket,
	}) {
		t.Fatal("begin retransmission state")
	}
	server.HandleRetransmitRekeyRequest(
		n3iwf_context.NewRetransmitRekeyRequestEvt(ikeSA.LocalSPI, 11))
	if err = receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	gotPacket := make([]byte, 32)
	length, _, err := receiver.ReadFromUDP(gotPacket)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPacket[:length], wantPacket) {
		t.Fatalf("retransmitted packet=%x want %x", gotPacket[:length], wantPacket)
	}
	request, ok := ikeSA.RekeyRequestSnapshot(11)
	if !ok || request.Retransmissions != 1 {
		t.Fatalf("retransmission state=%+v exists=%t", request, ok)
	}
}

func TestRekeyTimeoutClearsPendingExchange(t *testing.T) {
	app, err := NewN3iwfTestApp(NewTestCfg())
	if err != nil {
		t.Fatal(err)
	}
	defer app.cancel()
	app.cfg.Configuration.ChildSARekey = &factory.ChildSARekeyConfig{
		Enable: true, Lifetime: time.Minute, OverlapDuration: time.Second,
		RetransmitTime: time.Second, MaxRetransmits: 1,
	}
	server, err := NewServer(app)
	if err != nil {
		t.Fatal(err)
	}
	ikeSA := app.n3iwfCtx.NewIKESecurityAssociation()
	ikeUe := app.n3iwfCtx.NewN3iwfIkeUe(ikeSA.LocalSPI)
	ikeUe.N3IWFIKESecurityAssociation = ikeSA
	ikeSA.IkeUE = ikeUe
	ikeUe.CreateHalfChildSARekey(3, 2001, 1, 1001, bytes.Repeat([]byte{1}, 32))
	if !ikeSA.BeginRekeyRequest(n3iwf_context.RekeyRequestState{
		Kind: n3iwf_context.RekeyCreateRequest, MessageID: 3,
		OldInboundSPI: 1001, NewInboundSPI: 2001, Packet: []byte{1},
		Retransmissions: 1,
	}) {
		t.Fatal("begin timeout state")
	}
	server.HandleRetransmitRekeyRequest(
		n3iwf_context.NewRetransmitRekeyRequestEvt(ikeSA.LocalSPI, 3))
	if _, exists := ikeUe.TemporaryExchangeMsgIDChildSAMapping[3]; exists {
		t.Fatal("timed-out half Child SA was not discarded")
	}
	if ikeSA.OutstandingRequest.Load() {
		t.Fatal("timed-out request still owns the IKE request window")
	}
	if _, exists := ikeSA.RekeyRequestSnapshot(3); exists {
		t.Fatal("timed-out retransmission state still exists")
	}
}

func TestScheduledRekeyIsIgnoredAfterRanRelease(t *testing.T) {
	app, err := NewN3iwfTestApp(NewTestCfg())
	if err != nil {
		t.Fatal(err)
	}
	defer app.cancel()
	app.cfg.Configuration.ChildSARekey = &factory.ChildSARekeyConfig{
		Enable: true, Lifetime: time.Minute, OverlapDuration: time.Second,
		RetransmitTime: time.Second, MaxRetransmits: 1,
	}
	server, err := NewServer(app)
	if err != nil {
		t.Fatal(err)
	}
	ikeSA := app.n3iwfCtx.NewIKESecurityAssociation()
	ikeUe := app.n3iwfCtx.NewN3iwfIkeUe(ikeSA.LocalSPI)
	ikeUe.N3IWFIKESecurityAssociation = ikeSA
	ikeSA.IkeUE = ikeUe
	old := makeTestChildSA(t, ikeUe)
	old.PDUSessionIds = []int64{1}
	ikeUe.N3IWFChildSecurityAssociation[old.InboundSPI] = old

	// Deliberately omit the SPI-to-NGAP mapping: this is the state after RAN
	// context release but before a previously scheduled rekey timer fires.
	server.HandleRekeyChildSA(
		n3iwf_context.NewRekeyChildSAEvt(ikeSA.LocalSPI, old.InboundSPI))

	if len(ikeUe.TemporaryExchangeMsgIDChildSAMapping) != 0 ||
		ikeSA.OutstandingRequest.Load() {
		t.Fatal("released UE started a stale rekey transaction")
	}
}

func TestSimultaneousRekeyReturnsTemporaryFailure(t *testing.T) {
	ikeSA := &n3iwf_context.IKESecurityAssociation{}
	notifications := []*ike_message.Notification{{NotifyMessageType: ike_message.REKEY_SA}}
	if got := peerChildSARequestRejection(notifications, ikeSA); got != ike_message.NO_ADDITIONAL_SAS {
		t.Fatalf("idle rekey rejection=%d", got)
	}
	if !ikeSA.BeginRekeyRequest(n3iwf_context.RekeyRequestState{
		Kind: n3iwf_context.RekeyCreateRequest, MessageID: 9, Packet: []byte{1},
	}) {
		t.Fatal("begin local rekey")
	}
	if got := peerChildSARequestRejection(notifications, ikeSA); got != ike_message.TEMPORARY_FAILURE {
		t.Fatalf("simultaneous rekey rejection=%d want TEMPORARY_FAILURE", got)
	}
}
