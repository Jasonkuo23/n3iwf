package factory

import (
	"testing"
	"time"
)

func TestUserPlaneControlDefaults(t *testing.T) {
	cfg := &Config{Configuration: &Configuration{}}
	if got := cfg.GetN3iwfUPControlName(); got != "N3DP_CTRL" {
		t.Fatalf("control-name=%q", got)
	}
	if cfg.GetN3iwfUPControlTrace() {
		t.Fatal("control trace enabled by default")
	}
}

func TestUserPlaneControlOverride(t *testing.T) {
	cfg := &Config{Configuration: &Configuration{
		N3IWFUPControlName:  "N3DP_TEST",
		N3IWFUPEALArgs:      []string{"-l", "3", "--proc-type=secondary"},
		N3IWFUPControlTrace: true,
	}}
	if got := cfg.GetN3iwfUPControlName(); got != "N3DP_TEST" {
		t.Fatalf("control-name=%q", got)
	}
	args := cfg.GetN3iwfUPEALArgs()
	if len(args) != 3 || args[1] != "3" || !cfg.GetN3iwfUPControlTrace() {
		t.Fatal("control options not preserved")
	}
	args[1] = "9"
	if cfg.GetN3iwfUPEALArgs()[1] != "3" {
		t.Fatal("caller mutated configured EAL arguments")
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
