package nwucp

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
)

func nasEnvelope(payload []byte) []byte {
	envelope := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(envelope[:2], uint16(len(payload)))
	copy(envelope[2:], payload)
	return envelope
}

func TestServeConnPreservesNASMessageOrder(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	ranUe := &n3iwf_context.N3IWFRanUe{}
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	forwarded := make(chan string, 2)
	var serverWG sync.WaitGroup
	serverWG.Add(1)
	go serveConnWithForwarder(
		ranUe,
		serverConn,
		&serverWG,
		func(_ *n3iwf_context.N3IWFRanUe, packet []byte) {
			message := string(packet)
			if message == "registration-complete" {
				close(firstEntered)
				<-releaseFirst
			}
			forwarded <- message
		},
	)

	frames := append(nasEnvelope([]byte("registration-complete")),
		nasEnvelope([]byte("pdu-session-request"))...)
	writeDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(frames)
		writeDone <- err
	}()

	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first NAS message was not forwarded")
	}
	select {
	case message := <-forwarded:
		t.Fatalf("message %q completed while the first forward was blocked", message)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseFirst)
	for _, want := range []string{"registration-complete", "pdu-session-request"} {
		select {
		case got := <-forwarded:
			if got != want {
				t.Fatalf("forwarded message %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for %q", want)
		}
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write NAS frames: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out writing NAS frames")
	}

	if err := clientConn.Close(); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan struct{})
	go func() {
		serverWG.Wait()
		close(serverDone)
	}()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("NAS connection handler did not stop")
	}
}
