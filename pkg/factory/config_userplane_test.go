package factory

import (
	"testing"
	"time"
)

func TestUserPlaneBackendDefaults(t *testing.T) {
	cfg := &Config{Configuration: &Configuration{}}
	if got := cfg.GetUserPlaneBackend(); got != "linux" {
		t.Fatalf("backend=%q want linux", got)
	}
	if got := cfg.GetN3iwfDPControlSocket(); got != "/run/l25gc/n3iwf-dp.sock" {
		t.Fatalf("socket=%q", got)
	}
}

func TestUserPlaneBackendOverrides(t *testing.T) {
	cfg := &Config{Configuration: &Configuration{
		UserPlaneBackend:     "onvm",
		N3IWFDPControlSocket: "/tmp/test-n3iwf-dp.sock",
	}}
	if got := cfg.GetUserPlaneBackend(); got != "onvm" {
		t.Fatalf("backend=%q want onvm", got)
	}
	if got := cfg.GetN3iwfDPControlSocket(); got != "/tmp/test-n3iwf-dp.sock" {
		t.Fatalf("socket=%q", got)
	}
}

func TestChildSARekeyDefaultsDisabled(t *testing.T) {
	for _, cfg := range []*Config{{}, {Configuration: &Configuration{}}} {
		if got := cfg.GetChildSARekey(); got != (ChildSARekeyConfig{}) {
			t.Fatalf("unexpected default rekey policy: %+v", got)
		}
	}
}

func TestChildSARekeyOverride(t *testing.T) {
	want := ChildSARekeyConfig{
		Enable:          true,
		Lifetime:        10 * time.Minute,
		Jitter:          30 * time.Second,
		OverlapDuration: 2 * time.Second,
		RetransmitTime:  ChildSARekeyDefaultRetransmitTime,
		MaxRetransmits:  ChildSARekeyDefaultMaxRetransmits,
	}
	configured := want
	configured.Jitter = 0
	configured.RetransmitTime = 0
	configured.MaxRetransmits = 0
	cfg := &Config{Configuration: &Configuration{ChildSARekey: &configured}}
	if got := cfg.GetChildSARekey(); got != want {
		t.Fatalf("rekey policy=%+v want %+v", got, want)
	}
}

func TestChildSARekeyValidation(t *testing.T) {
	tests := []struct {
		name    string
		policy  ChildSARekeyConfig
		wantErr bool
	}{
		{name: "disabled zero values", policy: ChildSARekeyConfig{}},
		{name: "valid", policy: ChildSARekeyConfig{
			Enable: true, Lifetime: time.Minute, OverlapDuration: time.Second,
		}},
		{name: "missing lifetime", policy: ChildSARekeyConfig{Enable: true}, wantErr: true},
		{name: "negative overlap", policy: ChildSARekeyConfig{
			Enable: true, Lifetime: time.Minute, OverlapDuration: -time.Second,
		}, wantErr: true},
		{name: "jitter equals lifetime", policy: ChildSARekeyConfig{
			Enable: true, Lifetime: time.Minute, Jitter: time.Minute,
		}, wantErr: true},
		{name: "negative retransmit time", policy: ChildSARekeyConfig{
			Enable: true, Lifetime: time.Minute, RetransmitTime: -time.Second,
		}, wantErr: true},
		{name: "overlap equals lifetime", policy: ChildSARekeyConfig{
			Enable: true, Lifetime: time.Minute, OverlapDuration: time.Minute,
		}, wantErr: true},
		{name: "too many retransmits", policy: ChildSARekeyConfig{
			Enable: true, Lifetime: time.Minute, MaxRetransmits: 11,
		}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.policy.validate(); (err != nil) != test.wantErr {
				t.Fatalf("validate() error=%v wantErr=%t", err, test.wantErr)
			}
		})
	}
}

func TestAppendInvalidAcceptsPlainError(t *testing.T) {
	err := appendInvalid(assertionError("plain validation failure"))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

type assertionError string

func (err assertionError) Error() string { return string(err) }
