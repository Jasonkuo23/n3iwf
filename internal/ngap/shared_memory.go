package ngap

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/free5gc/n3iwf/internal/ngap/message"
	"github.com/free5gc/n3iwf/internal/ngap/transportcodec"
	n2 "github.com/nycu-ucr/l25gc-n2-transport"
)

func (s *Server) startSharedMemory(wg *sync.WaitGroup) error {
	configured := s.Config().Configuration.N2SharedMemory
	if configured == nil {
		return fmt.Errorf("n2SharedMemory is required for sctp-shm")
	}
	cfg := *configured
	cfg.Classify = transportcodec.Classify
	ep, err := n2.Open(cfg, false)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(s.CancelContext(), 10*time.Second)
	defer cancel()
	conn, err := ep.Dial(ctx)
	if err != nil {
		ep.Close()
		return err
	}
	s.shm = ep
	s.conn = append(s.conn, conn)
	message.SendNGSetupRequest(conn, s.Context())
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer conn.Close()
		buf := make([]byte, n2.MaxPDU)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				s.rcvPktCh.Send(ReceiveNGAPPacket{Conn: conn, Err: err})
				return
			}
			s.rcvPktCh.Send(ReceiveNGAPPacket{Conn: conn, Buf: append([]byte(nil), buf[:n]...)})
		}
	}()
	return nil
}
