package ngap

import (
	"context"
	"testing"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/userplane"
	"github.com/free5gc/n3iwf/pkg/factory"
)

type recordingDeleteUserPlane struct {
	deletes               int
	generation            uint64
	ueID                  uint64
	pduSessionID          uint32
	childDeletes          int
	childDeleteGeneration []uint64
	deletedSPIs           []uint32
}

func (*recordingDeleteUserPlane) Start(context.Context) error { return nil }
func (*recordingDeleteUserPlane) UpsertSession(context.Context, uint64, userplane.Session) error {
	return nil
}
func (r *recordingDeleteUserPlane) DeleteSession(
	_ context.Context,
	generation uint64,
	ueID uint64,
	pduSessionID uint32,
) error {
	r.deletes++
	r.generation = generation
	r.ueID = ueID
	r.pduSessionID = pduSessionID
	return nil
}
func (*recordingDeleteUserPlane) UpsertChildSA(context.Context, uint64, userplane.ChildSA) error {
	return nil
}
func (r *recordingDeleteUserPlane) DeleteChildSA(
	_ context.Context,
	generation uint64,
	ueID uint64,
	pduSessionID uint32,
	inboundSPI uint32,
) error {
	r.childDeletes++
	r.childDeleteGeneration = append(r.childDeleteGeneration, generation)
	r.deletedSPIs = append(r.deletedSPIs, inboundSPI)
	r.ueID = ueID
	r.pduSessionID = pduSessionID
	return nil
}
func (*recordingDeleteUserPlane) Close() error { return nil }

func TestDeletePDUSessionUserPlane(t *testing.T) {
	app, err := NewN3iwfTestApp(&factory.Config{Configuration: &factory.Configuration{}})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingDeleteUserPlane{}
	app.userPlane = recorder
	server, err := NewServer(app)
	if err != nil {
		t.Fatal(err)
	}
	pduSession := &n3iwf_context.PDUSession{Id: 10}
	if _, err := pduSession.NextUserPlaneGeneration(); err != nil {
		t.Fatal(err)
	}

	if err := server.deletePDUSessionUserPlane(42, pduSession); err != nil {
		t.Fatal(err)
	}
	if recorder.deletes != 1 || recorder.generation != 2 ||
		recorder.ueID != 42 || recorder.pduSessionID != 10 {
		t.Fatalf("unexpected delete: %+v", recorder)
	}
}

func TestDeletePDUSessionUserPlaneDeletesRekeyOverlapChildSAs(t *testing.T) {
	app, err := NewN3iwfTestApp(&factory.Config{Configuration: &factory.Configuration{}})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingDeleteUserPlane{}
	app.userPlane = recorder
	server, err := NewServer(app)
	if err != nil {
		t.Fatal(err)
	}
	pduSession := &n3iwf_context.PDUSession{Id: 10}
	oldSA := &n3iwf_context.ChildSecurityAssociation{
		InboundSPI: 1001, PDUSessionIds: []int64{10},
	}
	newSA := &n3iwf_context.ChildSecurityAssociation{
		InboundSPI: 2001, PDUSessionIds: []int64{10},
	}

	if err := server.deletePDUSessionUserPlane(0, pduSession, oldSA, newSA); err != nil {
		t.Fatal(err)
	}
	if recorder.deletes != 1 || recorder.generation != 1 ||
		recorder.childDeletes != 2 ||
		len(recorder.childDeleteGeneration) != 2 ||
		recorder.childDeleteGeneration[0] != 2 || recorder.childDeleteGeneration[1] != 3 ||
		len(recorder.deletedSPIs) != 2 ||
		recorder.deletedSPIs[0] != 1001 || recorder.deletedSPIs[1] != 2001 ||
		recorder.ueID != 0 || recorder.pduSessionID != 10 {
		t.Fatalf("unexpected session/Child-SA deletes: %+v", recorder)
	}
}

func TestChildSAsForPDUSessionExcludesOtherSession(t *testing.T) {
	matching := &n3iwf_context.ChildSecurityAssociation{
		InboundSPI: 1001, PDUSessionIds: []int64{10},
	}
	other := &n3iwf_context.ChildSecurityAssociation{
		InboundSPI: 2001, PDUSessionIds: []int64{11},
	}
	sharedInvalid := &n3iwf_context.ChildSecurityAssociation{
		InboundSPI: 3001, PDUSessionIds: []int64{10, 11},
	}
	ikeUe := &n3iwf_context.N3IWFIkeUe{
		N3IWFChildSecurityAssociation: map[uint32]*n3iwf_context.ChildSecurityAssociation{
			matching.InboundSPI:      matching,
			other.InboundSPI:         other,
			sharedInvalid.InboundSPI: sharedInvalid,
		},
	}

	got := childSAsForPDUSession(ikeUe, 10)
	if len(got) != 1 || got[0] != matching {
		t.Fatalf("unexpected Child SAs for PDU Session 10: %+v", got)
	}
}

func TestDeletePDUSessionUserPlaneAcceptsRanUeIDZero(t *testing.T) {
	app, err := NewN3iwfTestApp(&factory.Config{Configuration: &factory.Configuration{}})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingDeleteUserPlane{}
	app.userPlane = recorder
	server, err := NewServer(app)
	if err != nil {
		t.Fatal(err)
	}

	if err = server.deletePDUSessionUserPlane(0, &n3iwf_context.PDUSession{Id: 1}); err != nil {
		t.Fatalf("RAN UE NGAP ID zero was rejected: %v", err)
	}
	if recorder.deletes != 1 || recorder.ueID != 0 || recorder.pduSessionID != 1 {
		t.Fatalf("unexpected ID-zero delete: %+v", recorder)
	}
	if err = server.deletePDUSessionUserPlane(-1,
		&n3iwf_context.PDUSession{Id: 1}); err == nil {
		t.Fatal("negative RAN UE NGAP ID was accepted")
	}
}
