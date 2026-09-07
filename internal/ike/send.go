package ike

import (
	"net"

	"github.com/pkg/errors"

	"github.com/free5gc/ike"
	ike_message "github.com/free5gc/ike/message"
	"github.com/free5gc/ike/security"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/logger"
)

func SendIKEMessageToUE(
	udpConn *net.UDPConn,
	srcAddr, dstAddr *net.UDPAddr,
	message *ike_message.IKEMessage,
	ikeSAKey *security.IKESAKey,
) error {
	ikeLog := logger.IKELog
	ikeLog.Trace("Send IKE message to UE")
	ikeLog.Trace("Encoding...")
	pkt, err := EncodeIKEPacketToUE(srcAddr, message, ikeSAKey)
	if err != nil {
		return err
	}
	ikeLog.Trace("Sending...")
	return WriteIKEPacketToUE(udpConn, dstAddr, pkt)
}

func EncodeIKEPacketToUE(
	srcAddr *net.UDPAddr,
	message *ike_message.IKEMessage,
	ikeSAKey *security.IKESAKey,
) ([]byte, error) {
	if srcAddr == nil || message == nil {
		return nil, errors.New("EncodeIKEPacketToUE: nil address or message")
	}
	pkt, err := ike.EncodeEncrypt(message, ikeSAKey, ike_message.Role_Responder)
	if err != nil {
		return nil, errors.Wrapf(err, "EncodeIKEPacketToUE")
	}
	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if srcAddr.Port == 4500 {
		prependZero := make([]byte, 4)
		pkt = append(prependZero, pkt...)
	}
	return pkt, nil
}

func WriteIKEPacketToUE(udpConn *net.UDPConn, dstAddr *net.UDPAddr, pkt []byte) error {
	if udpConn == nil || dstAddr == nil || len(pkt) == 0 {
		return errors.New("WriteIKEPacketToUE: nil socket/address or empty packet")
	}
	n, err := udpConn.WriteToUDP(pkt, dstAddr)
	if err != nil {
		return errors.Wrapf(err, "WriteIKEPacketToUE")
	}
	if n != len(pkt) {
		return errors.Errorf("WriteIKEPacketToUE: not all data sent: total=%d sent=%d",
			len(pkt), n)
	}
	return nil
}

func SendUEInformationExchange(
	ikeSA *n3iwf_context.IKESecurityAssociation,
	ikeSAKey *security.IKESAKey,
	payload *ike_message.IKEPayloadContainer, initiator bool,
	response bool, messageID uint32, conn *net.UDPConn,
	ueAddr *net.UDPAddr, n3iwfAddr *net.UDPAddr,
) {
	ikeLog := logger.IKELog

	// Build IKE message
	responseIKEMessage := ike_message.NewMessage(ikeSA.RemoteSPI, ikeSA.LocalSPI,
		ike_message.INFORMATIONAL, response, initiator, messageID, nil)

	if payload != nil && len(*payload) > 0 {
		responseIKEMessage.Payloads = append(responseIKEMessage.Payloads, *payload...)
	}

	err := SendIKEMessageToUE(conn, n3iwfAddr, ueAddr, responseIKEMessage, ikeSAKey)
	if err != nil {
		ikeLog.Errorf("SendUEInformationExchange err: %+v", err)
		return
	}
}

func SendIKEDeleteRequest(n3iwfCtx *n3iwf_context.N3IWFContext, localSPI uint64) {
	ikeLog := logger.IKELog
	ikeUe, ok := n3iwfCtx.IkeUePoolLoad(localSPI)
	if !ok {
		ikeLog.Errorf("Cannot get IkeUE from SPI : %+v", localSPI)
		return
	}

	var deletePayload ike_message.IKEPayloadContainer
	deletePayload.BuildDeletePayload(ike_message.TypeIKE, 0, 0, nil)
	SendUEInformationExchange(ikeUe.N3IWFIKESecurityAssociation, ikeUe.N3IWFIKESecurityAssociation.IKESAKey,
		&deletePayload, false, false, ikeUe.N3IWFIKESecurityAssociation.ResponderMessageID,
		ikeUe.IKEConnection.Conn, ikeUe.IKEConnection.UEAddr, ikeUe.IKEConnection.N3IWFAddr)
}

func SendChildSADeleteRequest(
	ikeUe *n3iwf_context.N3IWFIkeUe,
	relaseList []int64,
) {
	ikeLog := logger.IKELog
	var deleteSPIs []uint32
	spiLen := uint16(0)
	for _, releaseItem := range relaseList {
		for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
			if len(childSA.PDUSessionIds) == 0 {
				ikeLog.Errorf("Child SA 0x%08x has no PDU Session ID", childSA.InboundSPI)
				return
			}
			if childSA.PDUSessionIds[0] == releaseItem {
				spi := childSA.OutboundSPI
				if spi == 0 {
					ikeLog.Error("SendChildSADeleteRequest outbound SPI is zero")
					return
				}
				deleteSPIs = append(deleteSPIs, spi)
				spiLen += 1
				err := ikeUe.DeleteChildSA(childSA)
				if err != nil {
					ikeLog.Errorf("Delete Child SA error : %v", err)
					return
				}
			}
		}
	}

	var deletePayload ike_message.IKEPayloadContainer
	deletePayload.BuildDeletePayload(ike_message.TypeESP, 4, spiLen, deleteSPIs)
	SendUEInformationExchange(ikeUe.N3IWFIKESecurityAssociation, ikeUe.N3IWFIKESecurityAssociation.IKESAKey,
		&deletePayload, false, false, ikeUe.N3IWFIKESecurityAssociation.ResponderMessageID,
		ikeUe.IKEConnection.Conn, ikeUe.IKEConnection.UEAddr, ikeUe.IKEConnection.N3IWFAddr)
}
