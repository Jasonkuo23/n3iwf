package ngap

import (
	n3context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/pkg/factory"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestN2LossReleasesAMFUEAndUserPlane(t *testing.T) {
	app, err := NewN3iwfTestApp(&factory.Config{Configuration: &factory.Configuration{}})
	if err != nil {
		t.Fatal(err)
	}
	defer app.cancel()
	recorder := &recordingDeleteUserPlane{}
	app.userPlane = recorder
	server, err := NewServer(app)
	if err != nil {
		t.Fatal(err)
	}
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	amf := app.n3iwfCtx.NewN3iwfAmf(local.RemoteAddr().String(), local)
	ue := &n3context.N3IWFRanUe{RanUeSharedCtx: n3context.RanUeSharedCtx{
		N3iwfCtx: app.n3iwfCtx, AMF: amf, RanUeNgapId: 0,
		PduSessionList: map[int64]*n3context.PDUSession{10: {Id: 10}},
	}}
	amf.N3iwfRanUeList[0] = ue
	app.n3iwfCtx.RANUePool.Store(int64(0), ue)
	app.n3iwfCtx.NGAPIdToIKESPI.Store(int64(0), uint64(123))
	var wg sync.WaitGroup
	wg.Add(1)
	go server.runNgapEventHandler(&wg)
	server.rcvPktCh.Send(ReceiveNGAPPacket{Conn: local, Err: io.EOF})
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup stalled")
	}
	if _, ok := app.n3iwfCtx.AMFPoolLoad(local.RemoteAddr().String()); ok {
		t.Fatal("AMF retained")
	}
	if _, ok := app.n3iwfCtx.RANUePool.Load(int64(0)); ok {
		t.Fatal("UE retained")
	}
	if recorder.deletes != 1 || recorder.ueID != 0 || recorder.pduSessionID != 10 {
		t.Fatalf("user-plane session retained: %+v", recorder)
	}
	select {
	case event := <-app.mockIkeEvtCh.GetRcvChan():
		if event.Type() != n3context.IKEDeleteRequest {
			t.Fatal("wrong IKE cleanup event")
		}
	default:
		t.Fatal("missing IKE cleanup event")
	}
}
