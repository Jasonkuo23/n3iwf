package userplane

import (
	"fmt"
	"math"
	"net"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
)

// BuildSession converts state that N3IWF legitimately owns into the N3DP
// session contract. The UE PDU address is unspecified because N3IWF transports
// NAS and does not learn the SMF-assigned address. Uplink identity is the
// IKE-assigned GRE/IPsec-inner NWu address; ESP processing will later bind it
// to the authenticated Child SA SPI.
func BuildSession(
	ranUeNgapID int64,
	pduSession *n3iwf_context.PDUSession,
	ikeUe *n3iwf_context.N3IWFIkeUe,
	n3iwfNWuAddress string,
	n3iwfN3Address string,
) (Session, error) {
	if ranUeNgapID <= 0 {
		return Session{}, fmt.Errorf("invalid RAN UE NGAP ID %d", ranUeNgapID)
	}
	if pduSession == nil || pduSession.Id <= 0 || pduSession.Id > math.MaxUint32 {
		return Session{}, fmt.Errorf("invalid PDU session")
	}
	if pduSession.GTPConnInfo == nil || pduSession.GTPConnInfo.IncomingTEID == 0 ||
		pduSession.GTPConnInfo.OutgoingTEID == 0 {
		return Session{}, fmt.Errorf("PDU Session[%d] has incomplete GTP tunnel state", pduSession.Id)
	}
	if len(pduSession.QFIList) != 1 || pduSession.QFIList[0] == 0 || pduSession.QFIList[0] > 63 {
		return Session{}, fmt.Errorf("PDU Session[%d] requires exactly one QFI in range 1..63", pduSession.Id)
	}
	if ikeUe == nil {
		return Session{}, fmt.Errorf("PDU Session[%d] has no IKE UE", pduSession.Id)
	}

	ueNWu := ikeUe.IPSecInnerIP.To4()
	n3iwfNWu := net.ParseIP(n3iwfNWuAddress).To4()
	n3iwfN3 := net.ParseIP(n3iwfN3Address).To4()
	upfN3 := net.ParseIP(pduSession.GTPConnInfo.UPFIPAddr).To4()
	if ueNWu == nil || n3iwfNWu == nil || n3iwfN3 == nil || upfN3 == nil {
		return Session{}, fmt.Errorf("PDU Session[%d] requires IPv4 NWu and N3 addresses", pduSession.Id)
	}

	return Session{
		UEID:            uint64(ranUeNgapID),
		PDUSessionID:    uint32(pduSession.Id),
		UplinkTEID:      pduSession.GTPConnInfo.OutgoingTEID,
		DownlinkTEID:    pduSession.GTPConnInfo.IncomingTEID,
		UEPDUAddress:    net.IPv4zero,
		N3IWFNWuAddress: n3iwfNWu,
		UENWuAddress:    ueNWu,
		N3IWFN3Address:  n3iwfN3,
		UPFN3Address:    upfN3,
		QFIs:            []uint8{pduSession.QFIList[0]},
	}, nil
}
