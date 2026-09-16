package ike

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/pkg/errors"

	ike_message "github.com/free5gc/ike/message"
	ike_security "github.com/free5gc/ike/security"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/logger"
)

const childSARekeyRetryDelay = time.Second

func rekeyRetransmitDelay(base time.Duration, retransmissions uint32) time.Duration {
	if retransmissions > 10 {
		retransmissions = 10
	}
	return base * time.Duration(uint64(1)<<retransmissions)
}

func buildChildSARekeyPayload(
	old *n3iwf_context.ChildSecurityAssociation,
	newInboundSPI uint32,
	nonce []byte,
) (ike_message.IKEPayloadContainer, error) {
	var payload ike_message.IKEPayloadContainer
	if old == nil || old.ChildSAKey == nil || old.InboundSPI == 0 ||
		newInboundSPI == 0 || len(nonce) < 16 {
		return nil, errors.New("incomplete Child-SA rekey request")
	}
	localIP := old.TrafficSelectorLocal.IP.To4()
	remoteIP := old.TrafficSelectorRemote.IP.To4()
	if localIP == nil || remoteIP == nil {
		return nil, errors.New("initial rekey profile supports IPv4 selectors only")
	}

	oldSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(oldSPI, old.InboundSPI)
	payload.BuildNotification(ike_message.TypeESP, ike_message.REKEY_SA, oldSPI, nil)

	proposal, err := old.ChildSAKey.ToProposal()
	if err != nil {
		return nil, errors.Wrap(err, "build equivalent Child-SA proposal")
	}
	proposal.ProposalNumber = 1
	proposal.ProtocolID = ike_message.TypeESP
	proposal.SPI = make([]byte, 4)
	binary.BigEndian.PutUint32(proposal.SPI, newInboundSPI)
	requestSA := payload.BuildSecurityAssociation()
	requestSA.Proposals = append(requestSA.Proposals, proposal)
	payload.BuildNonce(nonce)
	tsi := payload.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(
		ike_message.TS_IPV4_ADDR_RANGE, ike_message.IPProtocolAll,
		0, math.MaxUint16, localIP, localIP)
	tsr := payload.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(
		ike_message.TS_IPV4_ADDR_RANGE, ike_message.IPProtocolAll,
		0, math.MaxUint16, remoteIP, remoteIP)
	return payload, nil
}

func exactHostSelector(selector *ike_message.IndividualTrafficSelector, ip net.IP) bool {
	want := ip.To4()
	return selector != nil && want != nil &&
		selector.TSType == ike_message.TS_IPV4_ADDR_RANGE &&
		(selector.IPProtocolID == ike_message.IPProtocolAll ||
			selector.IPProtocolID == oldGREProtocol) &&
		selector.StartPort == 0 && selector.EndPort == math.MaxUint16 &&
		bytes.Equal(selector.StartAddress, want) && bytes.Equal(selector.EndAddress, want)
}

const oldGREProtocol = 47

func validateChildSARekeyResponse(
	old *n3iwf_context.ChildSecurityAssociation,
	securityAssociation *ike_message.SecurityAssociation,
	tsi *ike_message.TrafficSelectorInitiator,
	tsr *ike_message.TrafficSelectorResponder,
) (uint32, error) {
	if old == nil || old.ChildSAKey == nil || securityAssociation == nil ||
		len(securityAssociation.Proposals) != 1 {
		return 0, errors.New("rekey response must contain one Child-SA proposal")
	}
	proposal := securityAssociation.Proposals[0]
	if proposal.ProtocolID != ike_message.TypeESP || len(proposal.SPI) != 4 {
		return 0, errors.New("rekey response has invalid ESP SPI")
	}
	candidate, err := ike_security.NewChildSAKeyByProposal(proposal)
	if err != nil {
		return 0, errors.Wrap(err, "decode rekey response proposal")
	}
	if candidate.EncrKInfo.TransformID() != old.EncrKInfo.TransformID() ||
		candidate.EncrKInfo.GetKeyLength() != old.EncrKInfo.GetKeyLength() ||
		(candidate.IntegKInfo == nil) != (old.IntegKInfo == nil) ||
		candidate.EsnInfo.TransformID() != old.EsnInfo.TransformID() ||
		candidate.DhInfo != nil {
		return 0, errors.New("rekey response changed Child-SA algorithms")
	}
	if candidate.IntegKInfo != nil &&
		candidate.IntegKInfo.TransformID() != old.IntegKInfo.TransformID() {
		return 0, errors.New("rekey response changed Child-SA integrity algorithm")
	}
	if tsi == nil || len(tsi.TrafficSelectors) != 1 ||
		tsr == nil || len(tsr.TrafficSelectors) != 1 ||
		!exactHostSelector(tsi.TrafficSelectors[0], old.TrafficSelectorLocal.IP) ||
		!exactHostSelector(tsr.TrafficSelectors[0], old.TrafficSelectorRemote.IP) {
		return 0, errors.New("rekey response changed or narrowed traffic selectors")
	}
	spi := binary.BigEndian.Uint32(proposal.SPI)
	if spi == 0 {
		return 0, errors.New("rekey response ESP SPI is zero")
	}
	return spi, nil
}

func (s *Server) allocateChildSPI() (uint32, error) {
	var encoded [4]byte
	for attempts := 0; attempts < 64; attempts++ {
		if _, err := rand.Read(encoded[:]); err != nil {
			return 0, err
		}
		spi := binary.BigEndian.Uint32(encoded[:])
		if spi == 0 {
			continue
		}
		if _, exists := s.Context().ChildSA.Load(spi); !exists {
			return spi, nil
		}
	}
	return 0, errors.New("could not allocate a unique Child-SA SPI")
}

func (s *Server) enqueueIKEEventAfter(delay time.Duration, event n3iwf_context.IkeEvt) {
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			s.rcvEvtCh.Send(event)
		case <-s.CancelContext().Done():
		}
	}()
}

func (s *Server) scheduleChildSARekey(child *n3iwf_context.ChildSecurityAssociation) {
	policy := s.Config().GetChildSARekey()
	if !policy.Enable || child == nil ||
		child.IkeUE == nil || child.InboundSPI == 0 || child.SelectedIPProtocol != oldGREProtocol {
		return
	}
	delay := policy.Lifetime
	if policy.Jitter > 0 {
		var random [8]byte
		if _, err := rand.Read(random[:]); err == nil {
			delay += time.Duration(binary.BigEndian.Uint64(random[:]) %
				(uint64(policy.Jitter) + 1))
		}
	}
	s.enqueueIKEEventAfter(delay, n3iwf_context.NewRekeyChildSAEvt(
		child.IkeUE.N3IWFIKESecurityAssociation.LocalSPI, child.InboundSPI))
}

func (s *Server) ikeRequestPending(ikeUe *n3iwf_context.N3IWFIkeUe) bool {
	return ikeUe == nil || len(ikeUe.TemporaryExchangeMsgIDChildSAMapping) != 0 ||
		ikeUe.N3IWFIKESecurityAssociation.OutstandingRequest.Load() ||
		ikeUe.N3IWFIKESecurityAssociation.DPDReqRetransTimer != nil
}

func (s *Server) startRekeyRequest(
	ikeUe *n3iwf_context.N3IWFIkeUe,
	message *ike_message.IKEMessage,
	kind n3iwf_context.RekeyRequestKind,
	oldInboundSPI, newInboundSPI uint32,
) error {
	if ikeUe == nil || ikeUe.N3IWFIKESecurityAssociation == nil || message == nil {
		return errors.New("invalid outbound rekey request")
	}
	ikeSA := ikeUe.N3IWFIKESecurityAssociation
	if ikeSA.IKEConnection == nil || ikeSA.IKEConnection.Conn == nil ||
		ikeSA.IKEConnection.N3IWFAddr == nil || ikeSA.IKEConnection.UEAddr == nil {
		return errors.New("outbound rekey request has no IKE connection")
	}
	packet, err := EncodeIKEPacketToUE(ikeSA.IKEConnection.N3IWFAddr, message, ikeSA.IKESAKey)
	if err != nil {
		return err
	}
	request := n3iwf_context.RekeyRequestState{
		Kind: kind, MessageID: message.MessageID, OldInboundSPI: oldInboundSPI,
		NewInboundSPI: newInboundSPI, Packet: packet,
	}
	if !ikeSA.BeginRekeyRequest(request) {
		return errors.New("another outbound IKE request is pending")
	}
	if err = WriteIKEPacketToUE(ikeSA.IKEConnection.Conn,
		ikeSA.IKEConnection.UEAddr, packet); err != nil {
		_, _ = ikeSA.FinishRekeyRequest(message.MessageID, kind)
		return err
	}
	policy := s.Config().GetChildSARekey()
	s.enqueueIKEEventAfter(policy.RetransmitTime,
		n3iwf_context.NewRetransmitRekeyRequestEvt(ikeSA.LocalSPI, message.MessageID))
	return nil
}

func (s *Server) HandleRetransmitRekeyRequest(event *n3iwf_context.RetransmitRekeyRequestEvt) {
	ikeUe, ok := s.Context().IkeUePoolLoad(event.LocalSPI)
	if !ok {
		return
	}
	ikeSA := ikeUe.N3IWFIKESecurityAssociation
	request, ok := ikeSA.RekeyRequestSnapshot(event.MessageID)
	if !ok {
		return
	}
	policy := s.Config().GetChildSARekey()
	if request.Retransmissions >= policy.MaxRetransmits {
		_, _ = ikeSA.FinishRekeyRequest(request.MessageID, request.Kind)
		if request.Kind == n3iwf_context.RekeyCreateRequest {
			ikeUe.DiscardHalfChildSA(request.MessageID)
		}
		logger.IKELog.Errorf("Child-SA rekey request timed out after %d retransmissions: kind=%d messageID=%d",
			request.Retransmissions, request.Kind, request.MessageID)
		if ranNgapID, exists := s.Context().NgapIdLoad(ikeSA.LocalSPI); exists {
			s.SendNgapEvt(n3iwf_context.NewSendUEContextReleaseRequestEvt(
				ranNgapID, n3iwf_context.ErrRadioConnWithUeLost))
		}
		return
	}
	if err := WriteIKEPacketToUE(ikeSA.IKEConnection.Conn,
		ikeSA.IKEConnection.UEAddr, request.Packet); err != nil {
		logger.IKELog.Warnf("Retransmit Child-SA rekey request messageID=%d: %v",
			request.MessageID, err)
	} else {
		logger.IKELog.Infof("Retransmitted Child-SA rekey request messageID=%d attempt=%d",
			request.MessageID, request.Retransmissions+1)
	}
	if !ikeSA.CountRekeyRetransmission(request.MessageID) {
		return
	}
	s.enqueueIKEEventAfter(rekeyRetransmitDelay(policy.RetransmitTime,
		request.Retransmissions+1), event)
}

func (s *Server) HandleRekeyChildSA(event *n3iwf_context.RekeyChildSAEvt) {
	ikeUe, ok := s.Context().IkeUePoolLoad(event.LocalSPI)
	if !ok {
		return
	}
	ranNgapID, ok := s.Context().NgapIdLoad(event.LocalSPI)
	if !ok {
		// Rekey timers intentionally outlive their scheduling call. The RAN UE
		// may have been released while the timer was pending; never resurrect an
		// IKE transaction after its SPI-to-NGAP mapping has been removed.
		return
	}
	ranUe, ok := s.Context().RanUePoolLoad(ranNgapID)
	if !ok {
		return
	}
	old, ok := ikeUe.N3IWFChildSecurityAssociation[event.OldInboundSPI]
	if !ok || old == nil {
		return
	}
	if s.ikeRequestPending(ikeUe) {
		s.enqueueIKEEventAfter(childSARekeyRetryDelay, event)
		return
	}
	if len(old.PDUSessionIds) != 1 {
		logger.IKELog.Errorf("Cannot rekey Child SA 0x%08x with %d PDU-session IDs",
			old.InboundSPI, len(old.PDUSessionIds))
		return
	}
	if ranUe.GetSharedCtx().FindPDUSession(old.PDUSessionIds[0]) == nil {
		return
	}
	newSPI, err := s.allocateChildSPI()
	if err != nil {
		logger.IKELog.Errorf("Allocate rekey Child-SA SPI: %v", err)
		return
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		logger.IKELog.Errorf("Generate Child-SA rekey nonce: %v", err)
		return
	}
	payload, err := buildChildSARekeyPayload(old, newSPI, nonce)
	if err != nil {
		logger.IKELog.Errorf("Build Child-SA rekey request: %v", err)
		return
	}
	ikeSA := ikeUe.N3IWFIKESecurityAssociation
	messageID := ikeSA.ResponderMessageID
	ikeUe.CreateHalfChildSARekey(messageID, newSPI, old.PDUSessionIds[0],
		old.InboundSPI, nonce)
	for index := range nonce {
		nonce[index] = 0
	}
	message := ike_message.NewMessage(ikeSA.RemoteSPI, ikeSA.LocalSPI,
		ike_message.CREATE_CHILD_SA, false, false, messageID, payload)
	if err := s.startRekeyRequest(ikeUe, message, n3iwf_context.RekeyCreateRequest,
		old.InboundSPI, newSPI); err != nil {
		ikeUe.DiscardHalfChildSA(messageID)
		logger.IKELog.Errorf("Send Child-SA rekey request: %v", err)
		s.enqueueIKEEventAfter(childSARekeyRetryDelay, event)
		return
	}
	logger.IKELog.Infof("Sent Child-SA rekey request: old inbound SPI=0x%08x new inbound SPI=0x%08x messageID=%d",
		old.InboundSPI, newSPI, messageID)
}

func (s *Server) handleChildSARekeyResponse(
	message *ike_message.IKEMessage,
	securityAssociation *ike_message.SecurityAssociation,
	nonce *ike_message.Nonce,
	tsi *ike_message.TrafficSelectorInitiator,
	tsr *ike_message.TrafficSelectorResponder,
	notifications []*ike_message.Notification,
	ikeSA *n3iwf_context.IKESecurityAssociation,
) bool {
	ikeUe := ikeSA.IkeUE
	pending, ok := ikeUe.TemporaryExchangeMsgIDChildSAMapping[message.MessageID]
	if !ok || pending.RekeyOfInboundSPI == 0 {
		return false
	}
	if _, finished := ikeSA.FinishRekeyRequest(message.MessageID,
		n3iwf_context.RekeyCreateRequest); !finished {
		// Direct handler tests and upgrades from pre-transaction contexts may
		// have only the legacy outstanding marker.
		ikeSA.OutstandingRequest.Store(false)
	}
	old, oldExists := ikeUe.N3IWFChildSecurityAssociation[pending.RekeyOfInboundSPI]
	fail := func(err error) bool {
		logger.IKELog.Errorf("Child-SA rekey response rejected: %v", err)
		ikeUe.DiscardHalfChildSA(message.MessageID)
		ikeSA.ResponderMessageID++
		if oldExists {
			s.enqueueIKEEventAfter(childSARekeyRetryDelay,
				n3iwf_context.NewRekeyChildSAEvt(ikeSA.LocalSPI, old.InboundSPI))
		}
		return true
	}
	if !oldExists || old == nil {
		return fail(errors.New("replaced Child SA no longer exists"))
	}
	if err := rekeyErrorNotification(notifications); err != nil {
		return fail(err)
	}
	if nonce == nil || len(nonce.NonceData) < 16 {
		return fail(errors.New("missing or short responder nonce"))
	}
	outboundSPI, err := validateChildSARekeyResponse(old, securityAssociation, tsi, tsr)
	if err != nil {
		return fail(err)
	}
	keySeed := append(append([]byte(nil), pending.InitiatorNonce...), nonce.NonceData...)
	newChild, err := ikeUe.CompleteChildSA(message.MessageID, outboundSPI, securityAssociation)
	if err != nil {
		return fail(err)
	}
	defer func() {
		for index := range keySeed {
			keySeed[index] = 0
		}
		for index := range newChild.InitiatorNonce {
			newChild.InitiatorNonce[index] = 0
		}
		newChild.InitiatorNonce = nil
	}()
	newChild.LocalPublicIPAddr = append(net.IP(nil), old.LocalPublicIPAddr...)
	newChild.PeerPublicIPAddr = append(net.IP(nil), old.PeerPublicIPAddr...)
	newChild.TrafficSelectorLocal = cloneIPNet(old.TrafficSelectorLocal)
	newChild.TrafficSelectorRemote = cloneIPNet(old.TrafficSelectorRemote)
	newChild.SelectedIPProtocol = old.SelectedIPProtocol
	newChild.EnableEncapsulate = old.EnableEncapsulate
	newChild.N3IWFPort = old.N3IWFPort
	newChild.NATPort = old.NATPort
	newChild.LocalIsInitiator = true
	if err = newChild.ChildSAKey.GenerateKeyForChildSA(ikeSA.IKESAKey, keySeed); err != nil {
		_ = ikeUe.DeleteChildSA(newChild)
		return fail(errors.Wrap(err, "derive replacement Child-SA keys"))
	}

	ranNgapID, ok := s.Context().NgapIdLoad(ikeSA.LocalSPI)
	if !ok {
		_ = ikeUe.DeleteChildSA(newChild)
		return fail(errors.New("RAN UE NGAP ID is absent"))
	}
	ranUe, ok := s.Context().RanUePoolLoad(ranNgapID)
	if !ok || len(newChild.PDUSessionIds) != 1 {
		_ = ikeUe.DeleteChildSA(newChild)
		return fail(errors.New("PDU-session context is absent"))
	}
	pduSession := ranUe.GetSharedCtx().FindPDUSession(newChild.PDUSessionIds[0])
	if pduSession == nil {
		_ = ikeUe.DeleteChildSA(newChild)
		return fail(errors.New("PDU session is absent"))
	}
	if _, err = s.upsertChildSAUserPlane(ranNgapID, pduSession, newChild); err != nil {
		_ = ikeUe.DeleteChildSA(newChild)
		return fail(errors.Wrap(err, "program replacement Child SA"))
	}
	ikeSA.ResponderMessageID++
	policy := s.Config().GetChildSARekey()
	s.enqueueIKEEventAfter(policy.OverlapDuration,
		n3iwf_context.NewRetireRekeyChildSAEvt(ikeSA.LocalSPI,
			old.InboundSPI, newChild.InboundSPI))
	s.scheduleChildSARekey(newChild)
	logger.IKELog.Infof("Installed rekey overlap for PDU Session[%d]: old SPI=0x%08x new SPI=0x%08x",
		pduSession.Id, old.InboundSPI, newChild.InboundSPI)
	return true
}

func cloneIPNet(source net.IPNet) net.IPNet {
	return net.IPNet{
		IP: append(net.IP(nil), source.IP...), Mask: append(net.IPMask(nil), source.Mask...),
	}
}

func (s *Server) HandleRetireRekeyChildSA(event *n3iwf_context.RetireRekeyChildSAEvt) {
	ikeUe, ok := s.Context().IkeUePoolLoad(event.LocalSPI)
	if !ok {
		return
	}
	newChild, newExists := ikeUe.N3IWFChildSecurityAssociation[event.NewInboundSPI]
	old, oldExists := ikeUe.N3IWFChildSecurityAssociation[event.OldInboundSPI]
	if !newExists || newChild == nil || newChild.RekeyOfInboundSPI != event.OldInboundSPI {
		return
	}
	if !oldExists || old == nil {
		newChild.RekeyOfInboundSPI = 0
		return
	}
	if s.ikeRequestPending(ikeUe) {
		s.enqueueIKEEventAfter(childSARekeyRetryDelay, event)
		return
	}
	if len(old.PDUSessionIds) != 1 {
		logger.IKELog.Errorf("Cannot retire rekey Child SA 0x%08x: invalid PDU identity", old.InboundSPI)
		return
	}
	ranNgapID, ok := s.Context().NgapIdLoad(event.LocalSPI)
	if !ok {
		return
	}
	ranUe, ok := s.Context().RanUePoolLoad(ranNgapID)
	if !ok {
		return
	}
	pduSession := ranUe.GetSharedCtx().FindPDUSession(old.PDUSessionIds[0])
	if pduSession == nil {
		return
	}
	if err := s.sendRekeyDeleteRequest(ikeUe, old.InboundSPI, newChild.InboundSPI); err != nil {
		logger.IKELog.Errorf("Send old Child-SA delete: %v", err)
		s.enqueueIKEEventAfter(childSARekeyRetryDelay, event)
		return
	}
	logger.IKELog.Infof("Sent old Child-SA delete: PDU Session[%d] retired SPI=0x%08x active SPI=0x%08x",
		pduSession.Id, old.InboundSPI, newChild.InboundSPI)
}

func (s *Server) sendRekeyDeleteRequest(
	ikeUe *n3iwf_context.N3IWFIkeUe,
	inboundSPI, replacementInboundSPI uint32,
) error {
	if ikeUe == nil || inboundSPI == 0 {
		return errors.New("invalid Child-SA delete request")
	}
	ikeSA := ikeUe.N3IWFIKESecurityAssociation
	var payload ike_message.IKEPayloadContainer
	payload.BuildDeletePayload(ike_message.TypeESP, 4, 1, []uint32{inboundSPI})
	message := ike_message.NewMessage(ikeSA.RemoteSPI, ikeSA.LocalSPI,
		ike_message.INFORMATIONAL, false, false, ikeSA.ResponderMessageID, payload)
	return s.startRekeyRequest(ikeUe, message, n3iwf_context.RekeyDeleteRequest,
		inboundSPI, replacementInboundSPI)
}

func (s *Server) handleRekeyDeleteResponse(
	message *ike_message.IKEMessage,
	ikeSA *n3iwf_context.IKESecurityAssociation,
) bool {
	request, ok := ikeSA.FinishRekeyRequest(message.MessageID,
		n3iwf_context.RekeyDeleteRequest)
	if !ok {
		return false
	}
	if err := s.completeRekeyRetirement(ikeSA.IkeUE, request.OldInboundSPI,
		request.NewInboundSPI); err != nil {
		logger.IKELog.Errorf("Complete acknowledged Child-SA retirement: %v", err)
		s.enqueueIKEEventAfter(childSARekeyRetryDelay,
			n3iwf_context.NewRetireRekeyChildSAEvt(ikeSA.LocalSPI,
				request.OldInboundSPI, request.NewInboundSPI))
	}
	return true
}

func (s *Server) completeRekeyRetirement(
	ikeUe *n3iwf_context.N3IWFIkeUe,
	oldInboundSPI, newInboundSPI uint32,
) error {
	old, oldExists := ikeUe.N3IWFChildSecurityAssociation[oldInboundSPI]
	newChild, newExists := ikeUe.N3IWFChildSecurityAssociation[newInboundSPI]
	if !newExists || newChild == nil {
		return errors.New("replacement Child SA is absent")
	}
	if !oldExists || old == nil {
		newChild.RekeyOfInboundSPI = 0
		return nil
	}
	if len(old.PDUSessionIds) != 1 {
		return errors.New("retired Child SA has invalid PDU identity")
	}
	ranNgapID, ok := s.Context().NgapIdLoad(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
	if !ok {
		return errors.New("RAN UE NGAP ID is absent")
	}
	ranUe, ok := s.Context().RanUePoolLoad(ranNgapID)
	if !ok {
		return errors.New("RAN UE context is absent")
	}
	pduSession := ranUe.GetSharedCtx().FindPDUSession(old.PDUSessionIds[0])
	if pduSession == nil {
		return errors.New("PDU session is absent")
	}
	if _, err := s.retireChildSAUserPlane(ranNgapID, pduSession, old); err != nil {
		return err
	}
	if err := ikeUe.DeleteChildSA(old); err != nil {
		return err
	}
	newChild.RekeyOfInboundSPI = 0
	logger.IKELog.Infof("Completed Child-SA rekey for PDU Session[%d]: retired SPI=0x%08x active SPI=0x%08x",
		pduSession.Id, oldInboundSPI, newInboundSPI)
	return nil
}

func rekeyErrorNotification(notifications []*ike_message.Notification) error {
	for _, notification := range notifications {
		if notification != nil && notification.NotifyMessageType < 16384 {
			return fmt.Errorf("peer returned IKE notification %d", notification.NotifyMessageType)
		}
	}
	return nil
}

func peerChildSARequestRejection(
	notifications []*ike_message.Notification,
	ikeSA *n3iwf_context.IKESecurityAssociation,
) uint16 {
	for _, notification := range notifications {
		if notification == nil || notification.NotifyMessageType != ike_message.REKEY_SA {
			continue
		}
		ikeSA.RekeyRequestMu.Lock()
		pending := ikeSA.RekeyRequest != nil
		ikeSA.RekeyRequestMu.Unlock()
		if pending {
			return ike_message.TEMPORARY_FAILURE
		}
		return ike_message.NO_ADDITIONAL_SAS
	}
	return ike_message.NO_ADDITIONAL_SAS
}
