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
	// TS 38.413 permits RAN UE NGAP IDs starting at zero, and this N3IWF's
	// allocator intentionally issues zero for its first UE.
	if ranUeNgapID < 0 {
		return Session{}, fmt.Errorf("invalid RAN UE NGAP ID %d", ranUeNgapID)
	}
	if pduSession == nil || pduSession.Id <= 0 || pduSession.Id > math.MaxUint32 {
		return Session{}, fmt.Errorf("invalid PDU session")
	}
	if pduSession.GTPConnInfo == nil || pduSession.GTPConnInfo.IncomingTEID == 0 ||
		pduSession.GTPConnInfo.OutgoingTEID == 0 {
		return Session{}, fmt.Errorf("PDU Session[%d] has incomplete GTP tunnel state", pduSession.Id)
	}
	if len(pduSession.QFIList) == 0 || len(pduSession.QFIList) > 63 {
		return Session{}, fmt.Errorf("PDU Session[%d] requires 1..63 QFIs", pduSession.Id)
	}
	seenQFI := uint64(0)
	for _, qfi := range pduSession.QFIList {
		if qfi == 0 || qfi > 63 || seenQFI&(uint64(1)<<qfi) != 0 {
			return Session{}, fmt.Errorf("PDU Session[%d] has invalid or duplicate QFI %d", pduSession.Id, qfi)
		}
		seenQFI |= uint64(1) << qfi
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
		QFIs:            append([]uint8(nil), pduSession.QFIList...),
	}, nil
}
