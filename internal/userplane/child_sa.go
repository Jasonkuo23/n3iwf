package userplane

import (
	"fmt"
	"math"
	"net"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
)

// BuildChildSA converts negotiated IKEv2 state into the directionally explicit
// N3DP contract. Key slices are copied so serialization cannot mutate IKE state.
func BuildChildSA(ranUeNgapID int64, pduSessionID int64,
	child *n3iwf_context.ChildSecurityAssociation) (ChildSA, error) {
	if ranUeNgapID < 0 || pduSessionID < 0 || pduSessionID > math.MaxUint32 {
		return ChildSA{}, fmt.Errorf("invalid Child SA UE/PDU identity")
	}
	if child == nil || child.ChildSAKey == nil || child.EncrKInfo == nil ||
		child.InboundSPI == 0 || child.OutboundSPI == 0 {
		return ChildSA{}, fmt.Errorf("incomplete Child SA")
	}
	if child.N3IWFPort < 0 || child.N3IWFPort > math.MaxUint16 ||
		child.NATPort < 0 || child.NATPort > math.MaxUint16 {
		return ChildSA{}, fmt.Errorf("Child SA NAT-T port is outside uint16 range")
	}
	local, peer := child.LocalPublicIPAddr, child.PeerPublicIPAddr
	if local == nil || peer == nil || child.TrafficSelectorLocal.IP == nil ||
		child.TrafficSelectorRemote.IP == nil {
		return ChildSA{}, fmt.Errorf("Child SA addresses/selectors are incomplete")
	}

	inEnc := child.InitiatorToResponderEncryptionKey
	inInteg := child.InitiatorToResponderIntegrityKey
	outEnc := child.ResponderToInitiatorEncryptionKey
	outInteg := child.ResponderToInitiatorIntegrityKey
	if child.LocalIsInitiator {
		inEnc, outEnc = outEnc, inEnc
		inInteg, outInteg = outInteg, inInteg
	}
	var integrityID uint16
	if child.IntegKInfo != nil {
		integrityID = child.IntegKInfo.TransformID()
	}
	result := ChildSA{
		UEID: uint64(ranUeNgapID), PDUSessionID: uint32(pduSessionID),
		InboundSPI: child.InboundSPI, OutboundSPI: child.OutboundSPI,
		EncryptionID: child.EncrKInfo.TransformID(), IntegrityID: integrityID,
		ReplayWindow: 64, ESN: child.EsnInfo.GetNeedESN(),
		LocalAddress: append(net.IP(nil), local...), PeerAddress: append(net.IP(nil), peer...),
		LocalSelector:         append(net.IP(nil), child.TrafficSelectorLocal.IP...),
		PeerSelector:          append(net.IP(nil), child.TrafficSelectorRemote.IP...),
		IPProtocol:            child.SelectedIPProtocol,
		InboundEncryptionKey:  append([]byte(nil), inEnc...),
		InboundIntegrityKey:   append([]byte(nil), inInteg...),
		OutboundEncryptionKey: append([]byte(nil), outEnc...),
		OutboundIntegrityKey:  append([]byte(nil), outInteg...),
	}
	if child.EnableEncapsulate {
		result.NATT = true
		result.LocalPort = uint16(child.N3IWFPort)
		result.PeerPort = uint16(child.NATPort)
	}
	return result, nil
}

// ClearChildSAKeys erases temporary contract key copies after the synchronous
// control-socket acknowledgement. The authoritative IKE context remains.
func ClearChildSAKeys(sa *ChildSA) {
	if sa == nil {
		return
	}
	for _, key := range [][]byte{sa.InboundEncryptionKey, sa.InboundIntegrityKey,
		sa.OutboundEncryptionKey, sa.OutboundIntegrityKey} {
		for index := range key {
			key[index] = 0
		}
	}
}
