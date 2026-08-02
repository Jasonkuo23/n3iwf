package context

import (
	"math"
	"testing"
)

func TestPDUSessionUserPlaneGeneration(t *testing.T) {
	pduSession := &PDUSession{Id: 10}
	for want := uint64(1); want <= 2; want++ {
		got, err := pduSession.NextUserPlaneGeneration()
		if err != nil || got != want {
			t.Fatalf("generation=%d err=%v want=%d", got, err, want)
		}
	}
	pduSession.userPlaneGeneration = math.MaxUint64
	if _, err := pduSession.NextUserPlaneGeneration(); err == nil {
		t.Fatal("generation exhaustion accepted")
	}
}
