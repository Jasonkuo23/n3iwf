package transportcodec

import (
	"encoding/json"
	"github.com/nycu-ucr/l25gc-n2-transport/fixture"
	"os"
	"testing"
)

func TestPinnedNGAPVectors(t *testing.T) {
	data, err := os.ReadFile("../../../../../lib/n2-transport/tests/ngap-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []fixture.Vector
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			ue, err := Classify(v.PDU)
			if err != nil || ue != v.UE {
				t.Fatalf("ue=%v want=%v err=%v", ue, v.UE, err)
			}
		})
	}
	if _, err := Classify([]byte{0xff}); err == nil {
		t.Fatal("accepted malformed NGAP")
	}
}
